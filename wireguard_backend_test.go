package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type wgCall struct {
	name string
	args []string
}

type fakeWGRunner struct {
	interfaces       []string
	dump             []byte
	fail             map[string]error
	keepAfterUp      bool
	keepAfterDown    bool
	interfaceQueries int
	calls            []wgCall
}

type delayedReadinessWGRunner struct {
	mu           sync.Mutex
	firstObserve chan struct{}
	firstOnce    sync.Once
	active       bool
	queries      int
	calls        []wgCall
}

func (r *delayedReadinessWGRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, wgCall{name: name, args: append([]string(nil), args...)})
	if name == "wg-quick" && len(args) == 2 {
		switch args[0] {
		case "up":
			r.active = true
			return nil, nil
		case "down":
			r.active = false
			return nil, nil
		}
	}
	if name == "wg" && reflect.DeepEqual(args, []string{"show", "interfaces"}) {
		r.queries++
		if r.queries == 1 {
			r.firstOnce.Do(func() { close(r.firstObserve) })
			return nil, nil
		}
		if r.active {
			return []byte("alpha"), nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %s %s", name, strings.Join(args, " "))
}

func (r *delayedReadinessWGRunner) snapshot() (bool, []wgCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active, append([]wgCall(nil), r.calls...)
}

func (r *fakeWGRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	copyArgs := append([]string(nil), args...)
	r.calls = append(r.calls, wgCall{name: name, args: copyArgs})
	key := name + " " + strings.Join(args, " ")
	if err := r.fail[key]; err != nil {
		return nil, err
	}
	if name == "wg" && reflect.DeepEqual(args, []string{"show", "interfaces"}) {
		r.interfaceQueries++
		return []byte(strings.Join(r.interfaces, " ")), nil
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "dump" {
		return r.dump, nil
	}
	if name == "wg-quick" && len(args) == 2 {
		identifier := strings.TrimSuffix(filepathBase(args[1]), ".conf")
		switch args[0] {
		case "up":
			if !r.keepAfterUp {
				r.interfaces = append(r.interfaces, identifier)
			}
		case "down":
			if !r.keepAfterDown {
				r.interfaces = removeString(r.interfaces, identifier)
			}
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

func TestWireGuardObserveIgnoresUnmanagedInterfaces(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha", "beta")
	runner.interfaces = []string{"docker0", "alpha"}

	active, err := backend.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != profiles[0].ID {
		t.Fatalf("active profile = %+v", active)
	}
	runner.interfaces = []string{"docker0", "tailscale0"}
	active, err = backend.Observe(context.Background())
	if err != nil || len(active) != 0 {
		t.Fatalf("unmanaged observation = %+v, %v", active, err)
	}
}

func TestWireGuardObserveReturnsMultipleManagedInterfacesForCleanup(t *testing.T) {
	backend, _, runner, _ := testWireGuardBackend(t, "alpha", "beta")
	runner.interfaces = []string{"alpha", "beta"}
	active, err := backend.Observe(context.Background())
	if err != nil || len(active) != 2 {
		t.Fatalf("active = %+v, error = %v", active, err)
	}
}

func TestWireGuardObserveRejectsAmbiguousCatalogInterface(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendWireGuard, "first", "shared.conf")
	writeCatalogProfile(t, root, BackendWireGuard, "second", "shared.conf")
	catalog := testCatalog(t, root)
	runner := &fakeWGRunner{interfaces: []string{"shared"}, fail: map[string]error{}}
	backend := NewWireGuardBackend(catalog, runner, 0)
	if _, err := backend.Observe(context.Background()); err == nil {
		t.Fatalf("ambiguous interface error = %v", err)
	}
}

func TestWireGuardStartUsesResolvedPathAndProvesReadiness(t *testing.T) {
	backend, root, runner, profiles := testWireGuardBackend(t, "alpha")
	request := CatalogProfile{ID: profiles[0].ID, Path: "/attacker/controlled"}

	if err := backend.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	wantPath := root + "/wireguard/generic/alpha.conf"
	if len(runner.calls) < 2 || runner.calls[0].name != "wg-quick" || !reflect.DeepEqual(runner.calls[0].args, []string{"up", wantPath}) {
		t.Fatalf("start calls = %+v", runner.calls)
	}
	if runner.interfaceQueries == 0 {
		t.Fatal("start did not observe readiness")
	}
}

func TestWireGuardStartFailsWithoutReadiness(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	runner.keepAfterUp = true
	if err := backend.Start(context.Background(), profiles[0]); err == nil || !strings.Contains(err.Error(), "did not reach expected state") {
		t.Fatalf("start error = %v", err)
	}
}

func TestWireGuardStartCancellationAndDeadlineCleanPartialActivation(t *testing.T) {
	for _, test := range []struct {
		name      string
		newCtx    func() (context.Context, context.CancelFunc)
		wantError error
	}{
		{
			name: "cancellation",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantError: context.Canceled,
		},
		{
			name: "deadline",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 30*time.Millisecond)
			},
			wantError: context.DeadlineExceeded,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := secureCatalogRoot(t)
			writeCatalogProfile(t, root, BackendWireGuard, "generic", "alpha.conf")
			catalog := testCatalog(t, root)
			profiles, err := catalog.Profiles(BackendWireGuard)
			if err != nil || len(profiles) != 1 {
				t.Fatalf("profiles = %+v, %v", profiles, err)
			}
			runner := &delayedReadinessWGRunner{firstObserve: make(chan struct{})}
			backend := NewWireGuardBackend(catalog, runner, time.Hour)
			ctx, cancel := test.newCtx()
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- backend.Start(ctx, profiles[0]) }()
			select {
			case <-runner.firstObserve:
				if errors.Is(test.wantError, context.Canceled) {
					cancel()
				}
			case <-time.After(time.Second):
				t.Fatal("readiness observation was not reached")
			}
			select {
			case err := <-result:
				if !errors.Is(err, test.wantError) {
					t.Fatalf("Start error = %v, want %v", err, test.wantError)
				}
			case <-time.After(time.Second):
				t.Fatal("Start did not return within the cleanup bound")
			}
			active, calls := runner.snapshot()
			if active {
				t.Fatal("partially activated interface survived failed readiness")
			}
			want := []wgCall{
				{name: "wg-quick", args: []string{"up", profiles[0].Path}},
				{name: "wg", args: []string{"show", "interfaces"}},
				{name: "wg", args: []string{"show", "interfaces"}},
				{name: "wg-quick", args: []string{"down", profiles[0].Path}},
				{name: "wg", args: []string{"show", "interfaces"}},
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %+v, want %+v", calls, want)
			}
		})
	}
}

func TestWireGuardExecRunnerCleansUpPartiallyActivatedInterface(t *testing.T) {
	backend, profile, trace, state := testWireGuardExecBackend(t, true)

	err := backend.Start(context.Background(), profile)
	if err == nil || !strings.Contains(err.Error(), "start WireGuard profile") {
		t.Fatalf("Start error = %v", err)
	}
	if _, statErr := os.Stat(state); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("interface state remains after cleanup: %v", statErr)
	}
	assertTraceLines(t, trace,
		"wg-quick up "+profile.Path,
		"wg show interfaces",
		"wg-quick down "+profile.Path,
		"wg show interfaces",
	)
}

func TestWireGuardExecRunnerStopIsIdempotent(t *testing.T) {
	backend, profile, trace, _ := testWireGuardExecBackend(t, false)

	if err := backend.Start(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if err := backend.Stop(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if err := backend.Stop(context.Background(), profile); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	assertTraceLines(t, trace,
		"wg-quick up "+profile.Path,
		"wg show interfaces",
		"wg show interfaces",
		"wg-quick down "+profile.Path,
		"wg show interfaces",
		"wg show interfaces",
	)
}

func TestWireGuardStopProvesInterfaceAbsent(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	runner.interfaces = []string{"alpha", "unmanaged0"}
	if err := backend.Stop(context.Background(), profiles[0]); err != nil {
		t.Fatal(err)
	}
	if containsString(runner.interfaces, "alpha") {
		t.Fatalf("interfaces after stop = %v", runner.interfaces)
	}
	if runner.interfaceQueries == 0 {
		t.Fatal("stop did not observe absence")
	}
}

func TestWireGuardStopFailsWhenInterfaceRemains(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	runner.interfaces = []string{"alpha"}
	runner.keepAfterDown = true
	if err := backend.Stop(context.Background(), profiles[0]); err == nil || !strings.Contains(err.Error(), "did not reach expected state") {
		t.Fatalf("stop error = %v", err)
	}
}

func TestWireGuardCommandFailuresRemainVisible(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	runner.fail["wg-quick up "+profiles[0].Path] = errors.New("up failed")
	if err := backend.Start(context.Background(), profiles[0]); err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("start command error = %v", err)
	}
	runner.fail = map[string]error{"wg show interfaces": errors.New("wg failed")}
	if _, err := backend.Observe(context.Background()); err == nil || !strings.Contains(err.Error(), "wg failed") {
		t.Fatalf("observe command error = %v", err)
	}
}

func TestWireGuardMetricsSumEveryPeer(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	runner.dump = []byte("private\tpublic\t51820\toff\npeer1\tpsk\tep\t0.0.0.0/0\t1\t12\t34\t0\npeer2\tpsk\tep\t0.0.0.0/0\t2\t56\t78\t0\n")
	metrics, err := backend.Metrics(context.Background(), profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if metrics.ReceivedBytes != 68 || metrics.SentBytes != 112 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestWireGuardMetricsRejectMalformedAndOverflowingCounters(t *testing.T) {
	backend, _, runner, profiles := testWireGuardBackend(t, "alpha")
	for _, dump := range []string{
		"private\tpublic\t51820\toff\npeer\tpsk\tep\tallowed\t1\tnot-a-number\t2\t0\n",
		"private\tpublic\t51820\toff\npeer\tpsk\tep\tallowed\t1\t18446744073709551615\t2\t0\npeer2\tpsk\tep\tallowed\t1\t1\t2\t0\n",
	} {
		runner.dump = []byte(dump)
		if _, err := backend.Metrics(context.Background(), profiles[0]); err == nil {
			t.Fatalf("invalid dump accepted: %q", dump)
		}
	}
}

func TestWireGuardAvailabilityChecksCatalogAndCommandIndependently(t *testing.T) {
	backend, _, runner, _ := testWireGuardBackend(t, "alpha")
	if err := backend.Available(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.fail["wg show interfaces"] = errors.New("binary unavailable")
	if err := backend.Available(context.Background()); err == nil || !strings.Contains(err.Error(), "binary unavailable") {
		t.Fatalf("availability error = %v", err)
	}

	root := secureCatalogRoot(t)
	catalog := testCatalog(t, root)
	missing := NewWireGuardBackend(catalog, &fakeWGRunner{fail: map[string]error{}}, 0)
	if err := missing.Available(context.Background()); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("missing catalog error = %v", err)
	}
}

func testWireGuardBackend(t *testing.T, identifiers ...string) (*WireGuardBackend, string, *fakeWGRunner, []CatalogProfile) {
	t.Helper()
	root := secureCatalogRoot(t)
	for _, identifier := range identifiers {
		writeCatalogProfile(t, root, BackendWireGuard, "generic", identifier+".conf")
	}
	catalog := testCatalog(t, root)
	profiles, err := catalog.Profiles(BackendWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeWGRunner{fail: make(map[string]error)}
	return NewWireGuardBackend(catalog, runner, 0), root, runner, profiles
}

func filepathBase(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func removeString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func testWireGuardExecBackend(t *testing.T, failUp bool) (*WireGuardBackend, CatalogProfile, string, string) {
	t.Helper()
	root := secureCatalogRoot(t)
	profilePath := writeCatalogProfile(t, root, BackendWireGuard, "generic", "alpha.conf")
	catalog := testCatalog(t, root)
	profiles, err := catalog.Profiles(BackendWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	trace := filepath.Join(directory, "trace")
	state := filepath.Join(directory, "interface")
	wg := writeExecutable(t, directory, "wg", `#!/bin/sh
printf 'wg %s\n' "$*" >> "$WG_TRACE"
if [ "$1 $2" = "show interfaces" ] && [ -f "$WG_STATE" ]; then
  printf 'alpha\n'
fi
`)
	wgQuickBody := `#!/bin/sh
printf 'wg-quick %s\n' "$*" >> "$WG_TRACE"
case "$1" in
  up)
    printf 'alpha\n' > "$WG_STATE"
    ;;
  down)
    rm -f "$WG_STATE"
    ;;
esac
`
	if failUp {
		wgQuickBody += `if [ "$1" = "up" ]; then
  printf 'simulated partial activation\n' >&2
  exit 1
fi
`
	}
	wgQuick := writeExecutable(t, directory, "wg-quick", wgQuickBody)
	t.Setenv("WG_TRACE", trace)
	t.Setenv("WG_STATE", state)
	runner := execRunner{paths: map[string]string{"wg": wg, "wg-quick": wgQuick}}
	if profiles[0].Path != profilePath {
		t.Fatalf("profile path = %q, want %q", profiles[0].Path, profilePath)
	}
	return NewWireGuardBackend(catalog, runner, time.Millisecond), profiles[0], trace, state
}

func assertTraceLines(t *testing.T, path string, want ...string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command trace = %#v, want %#v", got, want)
	}
}
