package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const defaultOpenVPNConfigLimit = 1 << 20

var openVPNSecretFileDirectives = map[string]struct{}{
	"auth-user-pass": {},
	"ca":             {},
	"cert":           {},
	"crl-verify":     {},
	"key":            {},
	"pkcs12":         {},
	"tls-auth":       {},
	"tls-crypt":      {},
	"tls-crypt-v2":   {},
}

// OpenVPNConfigInspector validates the subset of configuration that affects
// process ownership and secret-file containment. Profiles remain trusted,
// root-managed OpenVPN configuration; this is not a safety sandbox.
type OpenVPNConfigInspector struct {
	MaxBytes     int64
	ValidateFile func(string) error
}

func (i OpenVPNConfigInspector) Inspect(profilePath, providerDir string) error {
	providerDir, err := filepath.Abs(providerDir)
	if err != nil {
		return fmt.Errorf("resolve provider directory: %w", err)
	}
	profilePath, err = filepath.Abs(profilePath)
	if err != nil {
		return fmt.Errorf("resolve OpenVPN profile: %w", err)
	}
	if !pathWithin(providerDir, profilePath) {
		return errors.New("OpenVPN profile is outside its provider directory")
	}
	if err := validatePrivateDirectory(providerDir); err != nil {
		return fmt.Errorf("validate OpenVPN provider directory: %w", err)
	}
	file, err := openNoFollow(profilePath)
	if err != nil {
		return fmt.Errorf("open OpenVPN profile: %w", err)
	}
	defer file.Close()
	if err := validatePrivateFileDescriptor(file); err != nil {
		return fmt.Errorf("validate OpenVPN profile: %w", err)
	}
	if i.ValidateFile != nil {
		if err := i.ValidateFile(profilePath); err != nil {
			return fmt.Errorf("validate OpenVPN profile: %w", err)
		}
	}

	limit := i.MaxBytes
	if limit <= 0 {
		limit = defaultOpenVPNConfigLimit
	}
	reader := bufio.NewReader(io.LimitReader(file, limit+1))
	logical, total, line := "", int64(0), 0
	for {
		physical, readErr := reader.ReadString('\n')
		total += int64(len(physical))
		line++
		if total > limit {
			return fmt.Errorf("OpenVPN profile exceeds %d bytes", limit)
		}
		physical = strings.TrimSuffix(strings.TrimSuffix(physical, "\n"), "\r")
		continued, fragment, err := openVPNContinuation(physical)
		if err != nil {
			return fmt.Errorf("OpenVPN config line %d: %w", line, err)
		}
		logical += fragment
		if continued {
			if readErr == io.EOF {
				return fmt.Errorf("OpenVPN config line %d: dangling continuation", line)
			}
		} else {
			if err := i.inspectLogicalLine(logical, providerDir); err != nil {
				return fmt.Errorf("OpenVPN config line %d: %w", line, err)
			}
			logical = ""
		}
		if readErr != nil {
			if readErr != io.EOF {
				return fmt.Errorf("read OpenVPN profile: %w", readErr)
			}
			break
		}
	}
	return nil
}

func (i OpenVPNConfigInspector) inspectLogicalLine(line, providerDir string) error {
	tokens, err := tokenizeOpenVPNLine(line)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}
	if tokens[0] == "" {
		return errors.New("empty directive")
	}
	directive := strings.ToLower(strings.TrimLeft(tokens[0], "-"))
	if directive == "config" || directive == "daemon" || directive == "writepid" || directive == "cd" || directive == "chroot" || strings.HasPrefix(directive, "management") {
		return fmt.Errorf("directive %q is not supported", directive)
	}
	// These directives name credential-bearing files not supported by the v0.1
	// confinement contract.
	switch directive {
	case "askpass", "auth-gen-token-secret", "http-proxy-user-pass", "secret":
		return fmt.Errorf("credential file directive %q is not supported", directive)
	}
	if directive == "socks-proxy" && len(tokens) > 3 {
		return errors.New("socks-proxy credential files are not supported")
	}
	if _, ok := openVPNSecretFileDirectives[directive]; !ok {
		return nil
	}
	if len(tokens) != 2 {
		return fmt.Errorf("directive %q requires exactly one file argument", directive)
	}
	if directive == "auth-user-pass" && tokens[1] == "stdin" {
		return errors.New("auth-user-pass must name a non-interactive credential file")
	}
	secretPath := tokens[1]
	if !filepath.IsAbs(secretPath) {
		secretPath = filepath.Join(providerDir, secretPath)
	}
	secretPath = filepath.Clean(secretPath)
	if !pathWithin(providerDir, secretPath) {
		return fmt.Errorf("directive %q references a file outside its provider directory", directive)
	}
	if err := validateConfinedPrivateFile(providerDir, secretPath); err != nil {
		return fmt.Errorf("validate %s file: %w", directive, err)
	}
	if i.ValidateFile != nil {
		if err := i.ValidateFile(secretPath); err != nil {
			return fmt.Errorf("validate %s file: %w", directive, err)
		}
	}
	return nil
}

func openVPNContinuation(line string) (bool, string, error) {
	inSingle, inDouble, escaped := false, false, false
	commentAt := -1
	for index, char := range line {
		if char < 0x20 && char != '\t' {
			return false, "", errors.New("control character in directive")
		}
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && !inSingle {
			escaped = true
			continue
		}
		if char == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if char == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && (char == '#' || char == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			commentAt = index
			break
		}
	}
	content := line
	if commentAt >= 0 {
		content = line[:commentAt]
		escaped = false
		for _, char := range content {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			}
		}
	}
	trimmed := strings.TrimRight(content, " \t")
	if escaped && strings.HasSuffix(trimmed, "\\") {
		return true, strings.TrimSuffix(trimmed, "\\"), nil
	}
	if inSingle || inDouble {
		return false, "", errors.New("unterminated quote")
	}
	return false, content, nil
}

func tokenizeOpenVPNLine(line string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	inSingle, inDouble, escaped, started := false, false, false, false
	flush := func() {
		if started {
			tokens = append(tokens, token.String())
			token.Reset()
			started = false
		}
	}
	for index, char := range line {
		if escaped {
			token.WriteRune(char)
			started, escaped = true, false
			continue
		}
		if char == '\\' && !inSingle {
			escaped, started = true, true
			continue
		}
		if char == '\'' && !inDouble {
			inSingle, started = !inSingle, true
			continue
		}
		if char == '"' && !inSingle {
			inDouble, started = !inDouble, true
			continue
		}
		if !inSingle && !inDouble {
			if (char == '#' || char == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
				break
			}
			if char == ' ' || char == '\t' {
				flush()
				continue
			}
		}
		token.WriteRune(char)
		started = true
	}
	if escaped {
		return nil, errors.New("dangling escape")
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return tokens, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "private-file"), nil
}

func validatePrivateRegularFile(path string) error {
	file, err := openNoFollow(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return validatePrivateFileDescriptor(file)
}

func validateConfinedPrivateFile(root, path string) error {
	for directory := filepath.Dir(path); directory != root; directory = filepath.Dir(directory) {
		if !pathWithin(root, directory) || directory == filepath.Dir(directory) {
			return errors.New("file parent escapes provider directory")
		}
		if err := validatePrivateDirectory(directory); err != nil {
			return fmt.Errorf("validate file parent %s: %w", directory, err)
		}
	}
	return validatePrivateRegularFile(path)
}

func validatePrivateFileDescriptor(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("permissions must be 0600, got %04o", info.Mode().Perm())
	}
	if os.Geteuid() == 0 && ownerUID(info) != 0 {
		return errors.New("must be owned by root")
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("must be a real directory")
	}
	if stat.Mode&0o777 != 0o700 {
		return fmt.Errorf("permissions must be 0700, got %04o", stat.Mode&0o777)
	}
	if os.Geteuid() == 0 && stat.Uid != 0 {
		return errors.New("must be owned by root")
	}
	return nil
}
