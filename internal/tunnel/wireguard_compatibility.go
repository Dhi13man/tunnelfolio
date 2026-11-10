package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/securefs"
)

const systemWireGuardDir = "/etc/wireguard"

type WireGuardCompatibilityChecker struct {
	Runner     CommandRunner
	RuntimeDir string
	Timeout    time.Duration
}

func (c WireGuardCompatibilityChecker) CheckWireGuard(data []byte) error {
	if c.Runner == nil || c.RuntimeDir == "" {
		return errors.New("WireGuard compatibility checker is not configured")
	}
	path, cleanup, err := c.stageProfile(data)
	if err != nil {
		return err
	}
	defer cleanup()
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

// stageProfile writes a uniquely named .conf that wg-quick will accept as an
// interface name (1-15 characters). Prefer /etc/wireguard because Ubuntu 26's
// AppArmor profile for wg-quick can deny reading profiles from /run, which is
// where Tunnelfolio otherwise stages inspect files.
func (c WireGuardCompatibilityChecker) stageProfile(data []byte) (string, func(), error) {
	if err := securefs.EnsurePrivateDir(systemWireGuardDir, os.Geteuid()); err == nil {
		return writeStagedProfile(systemWireGuardDir, data)
	}
	if err := securefs.EnsurePrivateDir(c.RuntimeDir, os.Geteuid()); err != nil {
		return "", nil, fmt.Errorf("prepare compatibility directory")
	}
	directory, err := os.MkdirTemp(c.RuntimeDir, "inspect-")
	if err != nil {
		return "", nil, fmt.Errorf("create compatibility directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", nil, fmt.Errorf("secure compatibility directory")
	}
	path, cleanup, err := writeStagedProfile(directory, data)
	if err != nil {
		_ = os.RemoveAll(directory)
		return "", nil, err
	}
	return path, func() {
		cleanup()
		_ = os.RemoveAll(directory)
	}, nil
}

func writeStagedProfile(directory string, data []byte) (string, func(), error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", nil, fmt.Errorf("create compatibility profile name")
	}
	path := filepath.Join(directory, "tf"+hex.EncodeToString(suffix[:])+".conf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", nil, fmt.Errorf("stage compatibility profile")
	}
	return path, func() { _ = os.Remove(path) }, nil
}
