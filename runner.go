package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct {
	paths map[string]string
}

func newExecRunnerFor(names ...string) (execRunner, error) {
	paths := make(map[string]string, len(names))
	for _, name := range names {
		path, err := resolveSecureCommand(name)
		if err != nil {
			return execRunner{}, err
		}
		paths[name] = path
	}
	return execRunner{paths: paths}, nil
}

func resolveSecureCommand(name string) (string, error) {
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

func (r execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, ok := r.paths[name]
	if !ok {
		return nil, fmt.Errorf("command %q is not allowed", name)
	}
	command := exec.CommandContext(ctx, path, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	return command.CombinedOutput()
}
