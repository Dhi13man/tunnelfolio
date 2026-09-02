package tunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecRunnerPinsArgumentsAndBoundsOutput(t *testing.T) {
	directory := t.TempDir()
	trace := filepath.Join(directory, "trace")
	command := writeExecutable(t, directory, "capture", `#!/bin/sh
printf '%s\n' "$@" > "$TRACE"
printf '1234567890'
`)
	t.Setenv("TRACE", trace)
	runner, err := NewPinnedExecRunner(map[string]string{"capture": command}, 5)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.Run(context.Background(), "capture", "one word", "$(not-executed)")
	if !errors.Is(err, ErrOutputLimit) || string(output) != "12345" {
		t.Fatalf("bounded run = %q, %v", output, err)
	}
	arguments, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if string(arguments) != "one word\n$(not-executed)\n" {
		t.Fatalf("arguments changed: %q", arguments)
	}
	if _, err := runner.Run(context.Background(), "sh", "-c", "true"); err == nil {
		t.Fatal("runner accepted a command outside its allowlist")
	}
}

func TestExecRunnerCancellationKillsProcessGroup(t *testing.T) {
	directory := t.TempDir()
	childPath := filepath.Join(directory, "child")
	command := writeExecutable(t, directory, "tree", `#!/bin/sh
sleep 60 &
child=$!
printf '%s\n' "$child" > "$CHILD_PATH"
wait "$child"
`)
	t.Setenv("CHILD_PATH", childPath)
	runner, err := NewPinnedExecRunner(map[string]string{"tree": command}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, "tree")
		done <- err
	}()
	child := waitForPID(t, childPath)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled command did not return")
	}
	waitForGone(t, child)
}

func TestResolveSecureCommandAcceptsRootOwnedSystemBinary(t *testing.T) {
	path, err := ResolveSecureCommand("true")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("resolved path %q is not absolute", path)
	}
}

func writeExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		// test-audit: allow=FIXED_SLEEP reason="bounded polling waits for PID-file publication and success still requires parseable content" owner="Dhi13man" expires=2027-09-02
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("PID was not published")
	return 0
}

func waitForGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		// test-audit: allow=FIXED_SLEEP reason="bounded polling waits for ESRCH and never treats timeout as process cleanup" owner="Dhi13man" expires=2027-09-02
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d survived cancellation", pid)
}
