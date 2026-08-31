package main

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

func TestExecRunnerUsesPinnedPathAndPreservesArguments(t *testing.T) {
	directory := t.TempDir()
	trace := filepath.Join(directory, "arguments")
	command := writeExecutable(t, directory, "capture", `#!/bin/sh
printf '%s\n' "$0" "$@" > "$TRACE"
`)
	t.Setenv("TRACE", trace)
	t.Setenv("PATH", filepath.Join(directory, "not-used"))
	runner := execRunner{paths: map[string]string{"capture": command}}

	output, err := runner.Run(context.Background(), "capture", "one word", "--flag=value", "$(not-executed)")
	if err != nil {
		t.Fatalf("Run: %v; output: %s", err, output)
	}
	got, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{command, "one word", "--flag=value", "$(not-executed)", ""}, "\n")
	if string(got) != want {
		t.Fatalf("captured argv = %q, want %q", got, want)
	}
}

func TestExecRunnerRejectsCommandOutsideAllowlist(t *testing.T) {
	runner := execRunner{paths: map[string]string{}}
	if _, err := runner.Run(context.Background(), "sh", "-c", "exit 0"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Run error = %v", err)
	}
}

func TestExecRunnerCancellationKillsProcessGroup(t *testing.T) {
	directory := t.TempDir()
	childPIDPath := filepath.Join(directory, "child-pid")
	command := writeExecutable(t, directory, "process-tree", `#!/bin/sh
sleep 60 &
child=$!
printf '%s\n' "$child" > "$CHILD_PID_PATH"
wait "$child"
`)
	t.Setenv("CHILD_PID_PATH", childPIDPath)
	runner := execRunner{paths: map[string]string{"process-tree": command}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, "process-tree")
		done <- err
	}()

	childPID := waitForPIDFile(t, childPIDPath)
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("Run error = %v; context error = %v", err, ctx.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	waitForProcessGone(t, childPID)
}

func TestResolveSecureCommandRejectsUnsafeBinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("negative ownership test requires an unprivileged test user")
	}
	directory := t.TempDir()
	command := writeExecutable(t, directory, "unsafe", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", directory)

	if _, err := resolveSecureCommand("unsafe"); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("non-root-owned command error = %v", err)
	}

	if err := os.Chmod(command, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSecureCommand("unsafe"); err == nil || !strings.Contains(err.Error(), "not writable by group or world") {
		t.Fatalf("writable command error = %v", err)
	}
}

func TestResolveSecureCommandAcceptsSecureSystemBinary(t *testing.T) {
	path, err := resolveSecureCommand("true")
	if err != nil {
		t.Fatalf("resolve true: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("resolved path = %q, want absolute path", path)
	}
}

func writeExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(contents)))
			if parseErr != nil {
				t.Fatalf("parse child PID: %v", parseErr)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("child PID was not published")
	return 0
}

func waitForProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("inspect descendant %d: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant process %d survived cancellation", pid)
}
