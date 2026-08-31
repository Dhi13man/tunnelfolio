package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var errNotExist = errors.New("state file does not exist")

const maxStateFileSize = 1 << 20

type stateWriteResult struct {
	Published bool
	Durable   bool
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory permissions %04o are too broad", info.Mode().Perm())
	}
	if os.Geteuid() == 0 && ownerUID(info) != 0 {
		return errors.New("state directory must be owned by root")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	resolvedAbsolute, err := filepath.Abs(resolved)
	if err != nil {
		return err
	}
	if filepath.Clean(absolute) != filepath.Clean(resolvedAbsolute) {
		return errors.New("state directory path must not contain symlinks")
	}
	return nil
}

func readJSON(path string, target any) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return errNotExist
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("state must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state permissions %04o are too broad", info.Mode().Perm())
	}
	if os.Geteuid() == 0 && ownerUID(info) != 0 {
		return errors.New("state must be owned by root")
	}
	if info.Size() > maxStateFileSize {
		return errors.New("state file is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateFileSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxStateFileSize {
		return errors.New("state file is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("state must contain exactly one JSON value")
	}
	return nil
}

func writeJSONAtomic(path string, value any) (stateWriteResult, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return stateWriteResult{}, err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".tunnelfolio-state-*")
	if err != nil {
		return stateWriteResult{}, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return stateWriteResult{}, err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return stateWriteResult{}, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return stateWriteResult{}, err
	}
	if err := temp.Close(); err != nil {
		return stateWriteResult{}, err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return stateWriteResult{}, err
	}
	result := stateWriteResult{Published: true}
	directory, err := os.Open(dir)
	if err != nil {
		return result, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return result, err
	}
	result.Durable = true
	return result, nil
}
