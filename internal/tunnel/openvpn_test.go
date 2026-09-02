package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOpenVPNBackendSplitReadinessAndGracefulShutdown(t *testing.T) {
	backend, profile := newFakeOpenVPNBackend(t, "split-ready", nil)
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	state := backend.State()
	if !state.Running || !state.Ready || !state.GroupPresent {
		t.Fatalf("active State() = %+v", state)
	}
	if err := backend.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if state := backend.State(); state != (OpenVPNProcessState{}) {
		t.Fatalf("stopped State() = %+v", state)
	}
}

func TestOpenVPNAdapterCarriesStableProfileIdentity(t *testing.T) {
	backend, path := newFakeOpenVPNBackend(t, "split-ready", nil)
	adapter, err := NewOpenVPNAdapter(backend)
	if err != nil {
		t.Fatal(err)
	}
	profile := Profile{ID: "tf_profile", Protocol: ProtocolOpenVPN, Identifier: "tfidentifier1", Path: path}
	if err := adapter.Start(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	observed, err := adapter.Observe(context.Background(), []Profile{profile})
	if err != nil || len(observed) != 1 || observed[0].ProfileID != profile.ID {
		t.Fatalf("observation = %+v, %v", observed, err)
	}
	status, err := adapter.Status(context.Background(), profile)
	if err != nil || status.State != "active" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if err := adapter.Stop(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if observed, err := adapter.Observe(context.Background(), []Profile{profile}); err != nil || len(observed) != 0 {
		t.Fatalf("post-stop observation = %+v, %v", observed, err)
	}
}

func TestOpenVPNBackendEarlyExitAndReadinessTimeoutCleanGroup(t *testing.T) {
	for _, mode := range []string{"early-exit", "never-ready", "spoofed-ready"} {
		t.Run(mode, func(t *testing.T) {
			backend, profile := newFakeOpenVPNBackend(t, mode, nil)
			if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err == nil {
				t.Fatal("Activate() succeeded")
			}
			if state := backend.State(); state != (OpenVPNProcessState{}) {
				t.Fatalf("State() after failed start = %+v", state)
			}
		})
	}
}

func TestOpenVPNBackendCancellationCleansProcess(t *testing.T) {
	backend, profile := newFakeOpenVPNBackend(t, "never-ready", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := backend.Activate(ctx, profile, filepath.Dir(profile)); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("Activate() error = %v", err)
	}
	if state := backend.State(); state != (OpenVPNProcessState{}) {
		t.Fatalf("State() = %+v", state)
	}
}

func TestOpenVPNBackendIdentityCaptureFailureCleansNewSession(t *testing.T) {
	childPIDFile := filepath.Join(t.TempDir(), "child-pid")
	backend, profile := newFakeOpenVPNBackend(t, "descendant", []string{"CHILD_PID_FILE=" + childPIDFile})
	var leaderPID int
	backend.opts.ReadIdentity = func(pid int) (processIdentity, error) {
		leaderPID = pid
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(childPIDFile); err == nil {
				break
			}
			// test-audit: allow=FIXED_SLEEP reason="bounded polling waits for child publication and success still requires the file" owner="Dhi13man" expires=2027-09-02
			time.Sleep(5 * time.Millisecond)
		}
		return processIdentity{}, errors.New("forced identity read failure")
	}
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err == nil {
		t.Fatal("Activate() succeeded")
	}
	if leaderPID == 0 {
		t.Fatal("identity reader did not receive the leader PID")
	}
	waitForTest(t, time.Second, func() bool { return !processGroupPresent(leaderPID) })
	data, err := os.ReadFile(childPIDFile)
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	waitForTest(t, time.Second, func() bool { return errors.Is(syscall.Kill(childPID, 0), syscall.ESRCH) })
}

func TestOpenVPNBackendCanceledDeactivateStillForcesAndReaps(t *testing.T) {
	backend, profile := newFakeOpenVPNBackend(t, "ignore-signals", []string{"TRACE=" + filepath.Join(t.TempDir(), "signals")})
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	pid := backend.proc.pid
	backend.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := backend.Deactivate(ctx); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if processGroupPresent(pid) {
		t.Fatalf("process group %d remains", pid)
	}
}

func TestOpenVPNBackendUnexpectedExitIsObserved(t *testing.T) {
	backend, profile := newFakeOpenVPNBackend(t, "unexpected-exit", nil)
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	waitForTest(t, time.Second, func() bool { return backend.State().UnexpectedExit })
	waitForTest(t, time.Second, func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return backend.proc == nil
	})
	state := backend.State()
	if state.Running || state.Ready || !state.UnexpectedExit || state.LastError == "" {
		t.Fatalf("State() = %+v", state)
	}
	if err := backend.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate() after exit error = %v", err)
	}
}

func TestOpenVPNAdapterReportsUnexpectedExitWithOwnedProfile(t *testing.T) {
	backend, path := newFakeOpenVPNBackend(t, "unexpected-exit", nil)
	adapter, err := NewOpenVPNAdapter(backend)
	if err != nil {
		t.Fatal(err)
	}
	exits := make(chan UnexpectedExit, 1)
	adapter.SetUnexpectedExitHandler(func(event UnexpectedExit) { exits <- event })
	profile := Profile{ID: "tf_profile", Protocol: ProtocolOpenVPN, Identifier: "tfidentifier1", Path: path}
	if err := adapter.Start(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	var event UnexpectedExit
	select {
	case event = <-exits:
	case <-time.After(time.Second):
		t.Fatal("unexpected exit was not reported")
	}
	if event.ProfileID != profile.ID || event.ExecutionPath != profile.Path || !event.CleanupProved {
		t.Fatalf("event = %+v", event)
	}
	observed, err := adapter.Observe(context.Background(), []Profile{profile})
	if err != nil || len(observed) != 0 {
		t.Fatalf("post-exit observation = %+v, %v", observed, err)
	}
}

func TestOpenVPNSignalsOnlyMatchingProcessIdentity(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "while :; do :; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	identity, err := readProcessIdentity(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	proc := &openVPNProcess{pid: command.Process.Pid, sessionID: -1, leaderStartTime: identity.startTime}
	if err := signalOwnedProcessGroup(proc, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("identity-mismatched process was signaled: %v", err)
	}
}

func TestOpenVPNSessionOwnershipRejectsReusedLeaderIdentity(t *testing.T) {
	proc := &openVPNProcess{pid: 42, sessionID: 42, leaderStartTime: 100}
	if member, err := belongsToOwnedSession(proc, processIdentity{pid: 42, sessionID: 42, startTime: 101}); err == nil || member {
		t.Fatalf("reused leader accepted: member=%v error=%v", member, err)
	}
	if member, err := belongsToOwnedSession(proc, processIdentity{pid: 43, sessionID: 42, startTime: 200}); err != nil || !member {
		t.Fatalf("owned descendant rejected: member=%v error=%v", member, err)
	}
}

func TestOpenVPNBackendEscalatesAndReapsEntireProcessGroup(t *testing.T) {
	trace := filepath.Join(t.TempDir(), "signals")
	backend, profile := newFakeOpenVPNBackend(t, "ignore-signals", []string{"TRACE=" + trace})
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	backend.mu.Lock()
	pid := backend.proc.pid
	backend.mu.Unlock()
	if err := backend.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if processGroupPresent(pid) {
		t.Fatalf("process group %d remains", pid)
	}
	contents, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "INT") || !strings.Contains(string(contents), "TERM") {
		t.Fatalf("signal trace = %q", contents)
	}
}

func TestOpenVPNBackendReapsDescendantProcessGroup(t *testing.T) {
	childFile := filepath.Join(t.TempDir(), "child-pid")
	backend, profile := newFakeOpenVPNBackend(t, "descendant", []string{"CHILD_PID_FILE=" + childFile})
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	contents, err := os.ReadFile(childFile)
	if err != nil {
		t.Fatal(err)
	}
	childPID := 0
	if _, err := fmt.Sscanf(string(contents), "%d", &childPID); err != nil {
		t.Fatal(err)
	}
	if err := backend.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if err := syscall.Kill(childPID, 0); err == nil || !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("descendant %d remains: %v", childPID, err)
	}
}

func TestOpenVPNBackendBoundsAndRedactsDiagnostics(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	backend, profile := newFakeOpenVPNBackend(t, "noisy", nil)
	backend.opts.Log = func(message string) {
		mu.Lock()
		logs = append(logs, message)
		mu.Unlock()
	}
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := backend.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 || len(logs) > 40 {
		t.Fatalf("log count = %d", len(logs))
	}
	for _, entry := range logs {
		if len(entry) > 4096 {
			t.Fatalf("unbounded log length = %d", len(entry))
		}
		if strings.Contains(entry, "hunter2") {
			t.Fatalf("secret leaked in log %q", entry)
		}
		if strings.Contains(entry, "/etc/provider") {
			t.Fatalf("secret path leaked in log %q", entry)
		}
		if strings.Contains(entry, "vpn.example.test") {
			t.Fatalf("profile endpoint leaked in log %q", entry)
		}
	}
}

func TestOpenVPNDiagnosticRedactionNeverReturnsProfileContent(t *testing.T) {
	canary := "customer-private-endpoint.example"
	for _, line := range []string{
		"TCP/UDP: Preserving recently used remote address: [AF_INET]" + canary + ":1194",
		"Attempting to establish TCP connection with [AF_INET]" + canary + ":443",
		"ordinary diagnostic " + canary,
	} {
		if got := redactOpenVPNDiagnostic(line); strings.Contains(got, canary) {
			t.Fatalf("redactor returned profile content: %q", got)
		}
	}
}

func TestOpenVPNBackendRefusesSecondOwnedProcess(t *testing.T) {
	backend, profile := newFakeOpenVPNBackend(t, "split-ready", nil)
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err != nil {
		t.Fatal(err)
	}
	if err := backend.Activate(context.Background(), profile, filepath.Dir(profile)); err == nil {
		t.Fatal("second Activate() succeeded")
	}
	if err := backend.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newFakeOpenVPNBackend(t *testing.T, mode string, extraEnv []string) (*OpenVPNBackend, string) {
	t.Helper()
	directory := privateTestDir(t)
	script := filepath.Join(directory, "openvpn")
	source := `#!/bin/sh
case "$OPENVPN_FAKE_MODE" in
  split-ready)
	trap 'exit 0' INT TERM
	printf 'Initialization Sequence '
	sleep 0.02
	printf 'Completed\n'
	while :; do :; done
    ;;
  early-exit)
    exit 7
    ;;
  never-ready)
    trap 'exit 0' INT TERM
    while :; do :; done
    ;;
  spoofed-ready)
    trap 'exit 0' INT TERM
    printf "PUSH: Received control message: 'route Initialization Sequence Completed still-pending'\n"
    while :; do :; done
    ;;
  unexpected-exit)
    printf 'Initialization Sequence Completed\n'
    sleep 0.05
    exit 9
    ;;
  ignore-signals)
	trap 'printf "INT\\n" >> "$TRACE"' INT
	trap 'printf "TERM\\n" >> "$TRACE"' TERM
	printf 'Initialization Sequence Completed\n'
    while :; do :; done
    ;;
  noisy)
	printf 'password=hunter2\n'
	printf 'warning about /etc/provider/opaque-credential-file\n'
	i=0
	while [ "$i" -lt 32 ]; do
		printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
		i=$((i + 1))
	done
	printf '\n'
    printf 'Initialization Sequence Completed\n'
    trap 'exit 0' INT TERM
	while :; do :; done
	;;
  descendant)
	sleep 1000 &
	child=$!
	trap 'kill "$child" 2>/dev/null || :; wait "$child" 2>/dev/null || :; exit 0' INT TERM
	printf '%s\n' "$child" > "$CHILD_PID_FILE"
	printf 'Initialization Sequence Completed\n'
	while :; do :; done
	;;
esac
`
	if err := os.WriteFile(script, []byte(source), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(directory, "client.ovpn")
	writePrivateTestFile(t, profile, "client\n")
	opts := OpenVPNBackendOptions{
		Command:         script,
		ReadyTimeout:    150 * time.Millisecond,
		InterruptWait:   100 * time.Millisecond,
		TerminateWait:   100 * time.Millisecond,
		KillWait:        300 * time.Millisecond,
		ValidateCommand: func(string) error { return nil },
		Env:             append([]string{"OPENVPN_FAKE_MODE=" + mode}, extraEnv...),
	}
	backend, err := NewOpenVPNBackend(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = backend.Shutdown(ctx)
	})
	return backend, profile
}

func waitForTest(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		// test-audit: allow=FIXED_SLEEP reason="bounded polling waits for the asserted process state rather than treating elapsed time as success" owner="Dhi13man" expires=2027-09-02
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not observed before timeout")
}

var _ = syscall.SIGINT
