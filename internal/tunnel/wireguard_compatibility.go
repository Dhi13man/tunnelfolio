package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/securefs"
)

type WireGuardCompatibilityChecker struct {
	Runner     CommandRunner
	RuntimeDir string
	Timeout    time.Duration
}

func (c WireGuardCompatibilityChecker) CheckWireGuard(data []byte) error {
	if c.Runner == nil || c.RuntimeDir == "" {
		return errors.New("WireGuard compatibility checker is not configured")
	}
	if err := securefs.EnsurePrivateDir(c.RuntimeDir, os.Geteuid()); err != nil {
		return fmt.Errorf("prepare compatibility directory")
	}
	directory, err := os.MkdirTemp(c.RuntimeDir, "inspect-")
	if err != nil {
		return fmt.Errorf("create compatibility directory")
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure compatibility directory")
	}
	path := filepath.Join(directory, "profile.conf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("stage compatibility profile")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := c.Runner.Run(ctx, "wg-quick", "strip", path); err != nil {
		return errors.New("wg-quick rejected the profile")
	}
	return nil
}
