package securefs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const DefaultJSONLimit = 1 << 20

var (
	ErrLocked   = errors.New("state directory is locked by another process")
	ErrNotExist = errors.New("file does not exist")
)

type WriteResult struct {
	Published bool
	Durable   bool
}

type Lock struct {
	file *os.File
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	return errors.Join(err, l.file.Close())
}

func EnsurePrivateDir(path string, requiredUID int) error {
	directory, err := openDirectory(path, requiredUID, true, true)
	if err != nil {
		return err
	}
	return directory.Close()
}

func OpenPrivateDir(path string, requiredUID int) (*os.File, error) {
	return openDirectory(path, requiredUID, false, true)
}

func OpenDirectory(path string) (*os.File, error) {
	return openDirectory(path, -1, false, false)
}

func openDirectory(path string, requiredUID int, create, validateFinal bool) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve directory: %w", err)
	}
	clean := filepath.Clean(absolute)
	if clean == string(os.PathSeparator) {
		return nil, errors.New("private directory cannot be the filesystem root")
	}

	currentFD, err := unix.Open(string(os.PathSeparator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(currentFD), "directory-root")
	parts := strings.Split(strings.TrimPrefix(clean, string(os.PathSeparator)), string(os.PathSeparator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = current.Close()
			return nil, errors.New("invalid directory path segment")
		}
		nextFD, openErr := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = current.Close()
				return nil, fmt.Errorf("create directory segment %q: %w", part, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		}
		if openErr != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open directory segment %q: %w", part, openErr)
		}
		next := os.NewFile(uintptr(nextFD), "directory-segment")
		_ = current.Close()
		current = next
		if index == len(parts)-1 && validateFinal {
			if err := validateDescriptor(int(current.Fd()), unix.S_IFDIR, 0o700, requiredUID); err != nil {
				_ = current.Close()
				return nil, fmt.Errorf("validate private directory: %w", err)
			}
		}
	}
	return current, nil
}

func AcquireLock(directory string, requiredUID int) (*Lock, error) {
	dir, err := OpenPrivateDir(directory, requiredUID)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), "state-lock")
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("validate state lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock state directory: %w", err)
	}
	return &Lock{file: file}, nil
}

func ReadJSON(path string, target any, maxBytes int64, requiredUID int) error {
	if maxBytes <= 0 {
		maxBytes = DefaultJSONLimit
	}
	directory, err := OpenPrivateDir(filepath.Dir(path), requiredUID)
	if err != nil {
		return err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return ErrNotExist
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "private-json")
	defer file.Close()
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("JSON file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("JSON file exceeds %d bytes", maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON file must contain exactly one value")
	}
	return nil
}

func WriteJSONAtomic(path string, value any, requiredUID int, checkpoint func(string) error) (WriteResult, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return WriteResult{}, err
	}
	data = append(data, '\n')
	directory, err := OpenPrivateDir(filepath.Dir(path), requiredUID)
	if err != nil {
		return WriteResult{}, err
	}
	defer directory.Close()
	if err := runCheckpoint(checkpoint, "before_temp_create"); err != nil {
		return WriteResult{}, err
	}
	tempName, err := randomName(".manifest-")
	if err != nil {
		return WriteResult{}, err
	}
	fd, err := unix.Openat(int(directory.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return WriteResult{}, err
	}
	temp := os.NewFile(uintptr(fd), tempName)
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = unix.Unlinkat(int(directory.Fd()), tempName, 0)
		}
	}()
	if err := runCheckpoint(checkpoint, "after_temp_create"); err != nil {
		return WriteResult{}, err
	}
	if _, err := temp.Write(data); err != nil {
		return WriteResult{}, err
	}
	if err := runCheckpoint(checkpoint, "after_temp_write"); err != nil {
		return WriteResult{}, err
	}
	if err := temp.Sync(); err != nil {
		return WriteResult{}, err
	}
	if err := runCheckpoint(checkpoint, "after_temp_sync"); err != nil {
		return WriteResult{}, err
	}
	if err := temp.Close(); err != nil {
		return WriteResult{}, err
	}
	if err := unix.Renameat(int(directory.Fd()), tempName, int(directory.Fd()), filepath.Base(path)); err != nil {
		return WriteResult{}, err
	}
	cleanup = false
	result := WriteResult{Published: true}
	if err := runCheckpoint(checkpoint, "after_publish"); err != nil {
		return result, err
	}
	if err := unix.Fsync(int(directory.Fd())); err != nil {
		return result, err
	}
	if err := runCheckpoint(checkpoint, "after_parent_sync"); err != nil {
		return result, err
	}
	result.Durable = true
	return result, nil
}

func WriteExclusive(directory *os.File, name string, data []byte, requiredUID int) error {
	limit := int64(len(data))
	if limit == 0 {
		limit = 1
	}
	_, err := WriteExclusiveFrom(directory, name, bytes.NewReader(data), limit, requiredUID)
	return err
}

func WriteExclusiveFrom(directory *os.File, name string, reader io.Reader, maxBytes int64, requiredUID int) (int64, error) {
	if err := ValidName(name); err != nil {
		return 0, err
	}
	if reader == nil || maxBytes <= 0 {
		return 0, errors.New("reader and positive file limit are required")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), "exclusive-file")
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		return 0, err
	}
	written, err := io.Copy(file, io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return written, err
	}
	if written > maxBytes {
		return written, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	if err := file.Sync(); err != nil {
		return written, err
	}
	if err := file.Close(); err != nil {
		return written, err
	}
	keep = true
	return written, nil
}

func MkdirExclusive(directory *os.File, name string, requiredUID int) (*os.File, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(directory.Fd()), name, 0o700); err != nil {
		return nil, err
	}
	child, err := OpenDirAt(directory, name, requiredUID)
	if err != nil {
		_ = unix.Unlinkat(int(directory.Fd()), name, unix.AT_REMOVEDIR)
		return nil, err
	}
	return child, nil
}

func OpenDirAt(directory *os.File, name string, requiredUID int) (*os.File, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	child := os.NewFile(uintptr(fd), "child-directory")
	if err := validateDescriptor(fd, unix.S_IFDIR, 0o700, requiredUID); err != nil {
		_ = child.Close()
		return nil, err
	}
	return child, nil
}

func ReadFileAt(directory *os.File, name string, maxBytes int64, requiredUID int) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, errors.New("file limit must be positive")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func RemoveTreeAt(directory *os.File, name string, requiredUID int) error {
	child, err := OpenDirAt(directory, name, requiredUID)
	if err != nil {
		return err
	}
	entries, readErr := child.ReadDir(-1)
	if readErr != nil {
		_ = child.Close()
		return readErr
	}
	for _, entry := range entries {
		entryName := entry.Name()
		if err := ValidName(entryName); err != nil {
			_ = child.Close()
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(child.Fd()), entryName, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = child.Close()
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := RemoveTreeAt(child, entryName, requiredUID); err != nil {
				_ = child.Close()
				return err
			}
		case unix.S_IFREG:
			if stat.Mode&0o777 != 0o600 || requiredUID >= 0 && int(stat.Uid) != requiredUID {
				_ = child.Close()
				return errors.New("refusing to remove an invalid private file")
			}
			if err := unix.Unlinkat(int(child.Fd()), entryName, 0); err != nil {
				_ = child.Close()
				return err
			}
		default:
			_ = child.Close()
			return errors.New("refusing to remove an unexpected file type")
		}
	}
	if err := child.Close(); err != nil {
		return err
	}
	return unix.Unlinkat(int(directory.Fd()), name, unix.AT_REMOVEDIR)
}

func ReadPrivateFile(path string, maxBytes int64, requiredUID int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("file limit must be positive")
	}
	directory, err := OpenPrivateDir(filepath.Dir(path), requiredUID)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func RenameNoReplace(oldDir *os.File, oldName string, newDir *os.File, newName string) error {
	if err := ValidName(oldName); err != nil {
		return err
	}
	if err := ValidName(newName); err != nil {
		return err
	}
	return unix.Renameat2(int(oldDir.Fd()), oldName, int(newDir.Fd()), newName, unix.RENAME_NOREPLACE)
}

func Sync(directory *os.File) error {
	return unix.Fsync(int(directory.Fd()))
}

func ValidName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return errors.New("invalid file name")
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f {
			return errors.New("file name contains a control character")
		}
	}
	return nil
}

func ValidatePrivateFile(path string, requiredUID int) error {
	directory, err := OpenPrivateDir(filepath.Dir(path), requiredUID)
	if err != nil {
		return err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	return validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID)
}

func SyncPrivateFile(path string, requiredUID int) error {
	directory, err := OpenPrivateDir(filepath.Dir(path), requiredUID)
	if err != nil {
		return err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	if err := validateDescriptor(fd, unix.S_IFREG, 0o600, requiredUID); err != nil {
		return err
	}
	return file.Sync()
}

func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, ErrNotExist)
}

func validateDescriptor(fd int, expectedType uint32, expectedMode uint32, requiredUID int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != expectedType {
		return errors.New("unexpected file type")
	}
	if stat.Mode&0o777 != expectedMode {
		return fmt.Errorf("permissions %04o, require %04o", stat.Mode&0o777, expectedMode)
	}
	if requiredUID >= 0 && int(stat.Uid) != requiredUID {
		return fmt.Errorf("owner uid %d, require %d", stat.Uid, requiredUID)
	}
	return nil
}

func randomName(prefix string) (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func runCheckpoint(checkpoint func(string) error, name string) error {
	if checkpoint == nil {
		return nil
	}
	return checkpoint(name)
}
