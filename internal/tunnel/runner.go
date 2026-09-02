package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const defaultOutputLimit = 64 << 10

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct {
	paths       map[string]string
	outputLimit int
}

func NewExecRunner(names ...string) (*ExecRunner, error) {
	paths := make(map[string]string, len(names))
	for _, name := range names {
		path, err := ResolveSecureCommand(name)
		if err != nil {
			return nil, err
		}
		paths[name] = path
	}
	return &ExecRunner{paths: paths, outputLimit: defaultOutputLimit}, nil
}

func NewPinnedExecRunner(paths map[string]string, outputLimit int) (*ExecRunner, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one command path is required")
	}
	copyPaths := make(map[string]string, len(paths))
	for name, path := range paths {
		if name == "" || path == "" || !filepath.IsAbs(path) {
			return nil, errors.New("pinned command names and paths must be non-empty and absolute")
		}
		copyPaths[name] = path
	}
	if outputLimit <= 0 {
		outputLimit = defaultOutputLimit
	}
	return &ExecRunner{paths: copyPaths, outputLimit: outputLimit}, nil
}

func ResolveSecureCommand(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("locate %s: %w", name, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", name, err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s links: %w", name, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s must be a regular executable not writable by group or world", path)
	}
	if ownerUID(info) != 0 {
		return "", fmt.Errorf("%s must be owned by root", path)
	}
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil {
			return "", fmt.Errorf("inspect command ancestor %s: %w", ancestor, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || ownerUID(info) != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("command ancestor %s must be a root-owned directory not writable by group or world", ancestor)
		}
		if ancestor == filepath.Dir(ancestor) {
			break
		}
	}
	return path, nil
}

func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, ok := r.paths[name]
	if !ok {
		return nil, fmt.Errorf("command %q is not allowed", name)
	}
	output := &boundedBuffer{limit: r.outputLimit}
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	err := command.Run()
	if output.Exceeded() {
		return output.Bytes(), errors.Join(ErrOutputLimit, err)
	}
	return output.Bytes(), err
}

type boundedBuffer struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		b.data = append(b.data, data[:remaining]...)
	}
	if remaining < len(data) {
		b.exceeded = true
	}
	return len(data), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...)
}

func (b *boundedBuffer) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

func ownerUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
