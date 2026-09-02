package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
)

type fakeBackend struct {
	protocol string

	mu              sync.Mutex
	active          map[string]bool
	startErr        map[string]error
	stopErr         map[string]error
	activateOnError map[string]bool
	startEntered    chan struct{}
	startRelease    chan struct{}
	starts          []string
	stops           []string
	startPaths      []string
	stopPaths       []string
	availabilityErr error
	observationErr  error
	observeEntered  chan struct{}
	observeRelease  chan struct{}
	statusErr       error
	exitHandler     func(tunnel.UnexpectedExit)
	shutdownErr     error
	shutdownSettles bool
	shutdownCalls   int
}

func (b *fakeBackend) Protocol() string { return b.protocol }

func (b *fakeBackend) Available(context.Context) error { return b.availabilityErr }

func (b *fakeBackend) Observe(ctx context.Context, candidates []tunnel.Profile) ([]tunnel.Observation, error) {
	b.mu.Lock()
	entered := b.observeEntered
	release := b.observeRelease
	b.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.observationErr != nil {
		return nil, b.observationErr
	}
	result := make([]tunnel.Observation, 0, len(b.active))
	for _, profile := range candidates {
		if b.active[profile.ID] {
			result = append(result, tunnel.Observation{ProfileID: profile.ID, Protocol: profile.Protocol, Identifier: profile.Identifier})
		}
	}
	return result, nil
}

func (b *fakeBackend) Start(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	b.starts = append(b.starts, profile.ID)
	b.startPaths = append(b.startPaths, profile.Path)
	if b.startEntered != nil {
		select {
		case b.startEntered <- struct{}{}:
		default:
		}
	}
	release := b.startRelease
	err := b.startErr[profile.ID]
	if err == nil || b.activateOnError[profile.ID] {
		b.active[profile.ID] = true
	}
	b.mu.Unlock()
	if release != nil {
		<-release
	}
	return err
}

func (b *fakeBackend) Stop(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stops = append(b.stops, profile.ID)
	b.stopPaths = append(b.stopPaths, profile.Path)
	if err := b.stopErr[profile.ID]; err != nil {
		return err
	}
	delete(b.active, profile.ID)
	return nil
}

func (b *fakeBackend) Status(context.Context, tunnel.Profile) (tunnel.ProtocolStatus, error) {
	if b.statusErr != nil {
		return tunnel.ProtocolStatus{}, b.statusErr
	}
	state := "active"
	if b.protocol == tunnel.ProtocolWireGuard {
		state = "interface_active"
	}
	return tunnel.ProtocolStatus{State: state}, nil
}

func (b *fakeBackend) SetUnexpectedExitHandler(handler func(tunnel.UnexpectedExit)) {
	b.mu.Lock()
	b.exitHandler = handler
	b.mu.Unlock()
}

func (b *fakeBackend) emitUnexpectedExit(event tunnel.UnexpectedExit) {
	b.mu.Lock()
	delete(b.active, event.ProfileID)
	b.mu.Unlock()
	b.notifyUnexpectedExit(event)
}

func (b *fakeBackend) notifyUnexpectedExit(event tunnel.UnexpectedExit) {
	b.mu.Lock()
	handler := b.exitHandler
	b.mu.Unlock()
	if handler != nil {
		handler(event)
	}
}

func TestStatusDistinguishesProtocolObservationFailure(t *testing.T) {
	manager, _, backends, installed := testManager(t, nil)
	backends[profiles.ProtocolWireGuard].active[installed[1].ID] = true
	backends[profiles.ProtocolWireGuard].statusErr = errors.New("diagnostic failed")
	status := manager.Status(context.Background())
	if !status.Connected || !status.ObservationAvailable || status.ProtocolStatus == nil || status.ProtocolStatus.State != "observation_unavailable" {
		t.Fatalf("status = %+v", status)
	}
	if status.LastError != "Protocol status could not be observed." {
		t.Fatalf("public error = %q", status.LastError)
	}
}

func TestUpdateMetadataReturnsFreshProtocolAvailability(t *testing.T) {
	managed, _, backends, installed := testManager(t, nil)
	backends[profiles.ProtocolOpenVPN].availabilityErr = errors.New("tooling unavailable")
	name := "Renamed office"
	updated, err := managed.UpdateMetadata(context.Background(), installed[0].ID, profiles.MetadataPatch{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != name || updated.Available || updated.Capabilities["connect"] || updated.UnavailableReason == "" {
		t.Fatalf("updated profile = %+v", updated)
	}
}

func (b *fakeBackend) Shutdown(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.shutdownCalls++
	if b.shutdownErr != nil {
		return b.shutdownErr
	}
	if b.shutdownSettles {
		b.observationErr = nil
		clear(b.active)
	}
	return nil
}

func TestConnectSwitchDisconnectPersistsDesiredState(t *testing.T) {
	manager, store, backends, installed := testManager(t, nil)
	if err := manager.Connect(context.Background(), installed[0].ID); err != nil {
		t.Fatal(err)
	}
	assertDesired(t, store, installed[0].ID)
	if err := manager.Connect(context.Background(), installed[1].ID); err != nil {
		t.Fatal(err)
	}
	assertDesired(t, store, installed[1].ID)
	if backends[profiles.ProtocolOpenVPN].active[installed[0].ID] || !backends[profiles.ProtocolWireGuard].active[installed[1].ID] {
		t.Fatalf("switch did not settle: openvpn=%v wireguard=%v", backends[profiles.ProtocolOpenVPN].active, backends[profiles.ProtocolWireGuard].active)
	}
	status := manager.Status(context.Background())
	if !status.Connected || status.Profile == nil || status.Profile.ID != installed[1].ID || status.ProtocolStatus == nil {
		t.Fatalf("status = %+v", status)
	}
	if err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDesired(t, store, "")
	if manager.Status(context.Background()).Connected {
		t.Fatal("disconnect left a connected status")
	}
}

func TestLifecycleExecutesVerifiedPrivateCopiesAndRejectsTampering(t *testing.T) {
	t.Run("start and stop use private copies", func(t *testing.T) {
		managed, store, backends, installed := testManager(t, nil)
		if err := managed.Connect(context.Background(), installed[1].ID); err != nil {
			t.Fatal(err)
		}
		startPath := backends[profiles.ProtocolWireGuard].startPaths[0]
		if startPath == store.ObjectPath(installed[1]) || !strings.Contains(startPath, "/.executions/") {
			t.Fatalf("start path = %q", startPath)
		}
		if err := managed.Disconnect(context.Background()); err != nil {
			t.Fatal(err)
		}
		stopPath := backends[profiles.ProtocolWireGuard].stopPaths[0]
		if stopPath == store.ObjectPath(installed[1]) || stopPath == startPath || !strings.Contains(stopPath, "/.executions/") {
			t.Fatalf("stop path = %q", stopPath)
		}
		for _, path := range []string{startPath, stopPath} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("execution copy %q survived: %v", path, err)
			}
		}
	})

	for _, protocol := range []string{profiles.ProtocolOpenVPN, profiles.ProtocolWireGuard} {
		t.Run(protocol+" tamper", func(t *testing.T) {
			managed, store, backends, installed := testManager(t, nil)
			profile := installed[0]
			marker := filepath.Join(t.TempDir(), "executed")
			payload := []byte("\nup " + marker + "\n")
			if protocol == profiles.ProtocolWireGuard {
				profile = installed[1]
				payload = []byte("\nPostUp = touch " + marker + "\n")
			}
			file, err := os.OpenFile(store.ObjectPath(profile), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(payload); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := managed.Connect(context.Background(), profile.ID); err == nil {
				t.Fatal("tampered profile connected")
			}
			if len(backends[protocol].starts) != 0 {
				t.Fatalf("backend received tampered profile: %v", backends[protocol].starts)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tampered hook marker exists: %v", err)
			}
		})
	}
}

func TestFailedSwitchRestoresPreviousTunnel(t *testing.T) {
	manager, store, backends, installed := testManager(t, nil)
	if err := manager.Connect(context.Background(), installed[0].ID); err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolWireGuard].startErr[installed[1].ID] = errors.New("readiness failed")
	if err := manager.Connect(context.Background(), installed[1].ID); err == nil {
		t.Fatal("failed target returned nil")
	}
	if !backends[profiles.ProtocolOpenVPN].active[installed[0].ID] || backends[profiles.ProtocolWireGuard].active[installed[1].ID] {
		t.Fatalf("previous tunnel was not restored: %+v %+v", backends[profiles.ProtocolOpenVPN].active, backends[profiles.ProtocolWireGuard].active)
	}
	assertDesired(t, store, installed[0].ID)
}

func TestFailedStopNeverStartsTarget(t *testing.T) {
	manager, _, backends, installed := testManager(t, nil)
	if err := manager.Connect(context.Background(), installed[0].ID); err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolOpenVPN].stopErr[installed[0].ID] = errors.New("process remains")
	if err := manager.Connect(context.Background(), installed[1].ID); err == nil {
		t.Fatal("failed stop returned nil")
	}
	if len(backends[profiles.ProtocolWireGuard].starts) != 0 {
		t.Fatalf("target started after uncertain stop: %v", backends[profiles.ProtocolWireGuard].starts)
	}
}

func TestUnprovedTargetCleanupDoesNotRestorePreviousIntoConflict(t *testing.T) {
	manager, _, backends, installed := testManager(t, nil)
	if err := manager.Connect(context.Background(), installed[0].ID); err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolWireGuard].startErr[installed[1].ID] = errors.Join(errors.New("activation failed"), tunnel.ErrCleanupUnproved)
	if err := manager.Connect(context.Background(), installed[1].ID); !errors.Is(err, ErrManagedStateConflict) {
		t.Fatalf("unproved cleanup returned %v", err)
	}
	if len(backends[profiles.ProtocolOpenVPN].starts) != 1 {
		t.Fatalf("previous tunnel was restarted after unproved cleanup: %v", backends[profiles.ProtocolOpenVPN].starts)
	}
}

func TestPersistenceAmbiguityRollsBackNetworkAndReconcilesManifest(t *testing.T) {
	fail := false
	manager, store, backends, installed := testManager(t, func(name string) error {
		if fail && name == "manifest_after_publish" {
			fail = false
			return errors.New("injected parent sync failure")
		}
		return nil
	})
	fail = true
	if err := manager.Connect(context.Background(), installed[0].ID); !errors.Is(err, profiles.ErrOutcomeAmbiguous) {
		t.Fatalf("connect returned %v", err)
	}
	if backends[profiles.ProtocolOpenVPN].active[installed[0].ID] {
		t.Fatal("target remained active after persistence ambiguity")
	}
	assertDesired(t, store, "")
}

func TestPersistenceCompensationUncertaintyIsStickyConflict(t *testing.T) {
	t.Run("target cleanup fails", func(t *testing.T) {
		fail := false
		managed, _, backends, installed := testManager(t, func(name string) error {
			if fail && name == "manifest_after_publish" {
				fail = false
				return errors.New("persist failed")
			}
			return nil
		})
		target := installed[0]
		backends[profiles.ProtocolOpenVPN].stopErr[target.ID] = errors.New("cleanup failed")
		fail = true
		if err := managed.Connect(context.Background(), target.ID); !errors.Is(err, ErrManagedStateConflict) {
			t.Fatalf("Connect() error = %v", err)
		}
		if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" {
			t.Fatalf("status = %+v", status)
		}
	})

	t.Run("previous restoration fails", func(t *testing.T) {
		fail := false
		managed, store, backends, installed := testManager(t, func(name string) error {
			if fail && name == "manifest_after_publish" {
				fail = false
				return errors.New("persist failed")
			}
			return nil
		})
		previous, target := installed[0], installed[1]
		if err := managed.Connect(context.Background(), previous.ID); err != nil {
			t.Fatal(err)
		}
		backends[profiles.ProtocolOpenVPN].startErr[previous.ID] = errors.New("restore failed")
		fail = true
		if err := managed.Connect(context.Background(), target.ID); !errors.Is(err, ErrManagedStateConflict) {
			t.Fatalf("Connect() error = %v", err)
		}
		if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" {
			t.Fatalf("status = %+v", status)
		}
		manifest := store.Snapshot()
		if manifest.DesiredProfile != previous.ID || manifest.ConnectedAt != 0 {
			t.Fatalf("manifest = %+v", manifest)
		}
	})

	t.Run("state reconciliation fails", func(t *testing.T) {
		failPublish := false
		failReconcile := false
		managed, _, _, installed := testManager(t, func(name string) error {
			switch {
			case failPublish && name == "manifest_after_publish":
				failPublish = false
				failReconcile = true
				return errors.New("persist failed")
			case failReconcile && name == "manifest_before_temp_create":
				failReconcile = false
				return errors.New("reconcile failed")
			default:
				return nil
			}
		})
		failPublish = true
		if err := managed.Connect(context.Background(), installed[0].ID); !errors.Is(err, ErrManagedStateConflict) {
			t.Fatalf("Connect() error = %v", err)
		}
		if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" {
			t.Fatalf("status = %+v", status)
		}
	})

	t.Run("durability repair fails", func(t *testing.T) {
		fail := false
		manifestPath := ""
		managed, store, _, installed := testManager(t, func(name string) error {
			if fail && name == "manifest_after_publish" {
				fail = false
				if err := os.WriteFile(manifestPath, []byte("corrupt\n"), 0o600); err != nil {
					return err
				}
				return errors.New("persist failed")
			}
			return nil
		})
		manifestPath = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(store.ObjectPath(installed[0]))))), "manifest.json")
		fail = true
		if err := managed.Connect(context.Background(), installed[0].ID); !errors.Is(err, ErrManagedStateConflict) {
			t.Fatalf("Connect() error = %v", err)
		}
		if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" {
			t.Fatalf("status = %+v", status)
		}
	})
}

func TestRemoveBlocksActiveAndSharesTransitionAdmission(t *testing.T) {
	manager, store, backends, installed := testManager(t, nil)
	if err := manager.Connect(context.Background(), installed[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Remove(context.Background(), installed[0].ID); !errors.Is(err, ErrActiveProfile) {
		t.Fatalf("active removal returned %v", err)
	}
	backends[profiles.ProtocolWireGuard].startEntered = make(chan struct{}, 1)
	backends[profiles.ProtocolWireGuard].startRelease = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- manager.Connect(context.Background(), installed[1].ID) }()
	<-backends[profiles.ProtocolWireGuard].startEntered
	if _, err := manager.Remove(context.Background(), installed[0].ID); !errors.Is(err, ErrTransitionInProgress) {
		t.Fatalf("concurrent removal returned %v", err)
	}
	close(backends[profiles.ProtocolWireGuard].startRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	removed, err := manager.Remove(context.Background(), installed[0].ID)
	if err != nil || removed.Profile.ID != installed[0].ID {
		t.Fatalf("inactive removal = %+v, %v", removed, err)
	}
	if _, found := store.Snapshot().Profile(installed[0].ID); found {
		t.Fatal("removed profile remained in manifest")
	}
}

func TestRemoveRequiresTargetProtocolObservation(t *testing.T) {
	t.Run("missing target observer blocks removal", func(t *testing.T) {
		managed, store, _, installed := testManager(t, nil)
		delete(managed.backends, profiles.ProtocolWireGuard)
		if _, err := managed.Remove(context.Background(), installed[1].ID); !errors.Is(err, tunnel.ErrUnavailable) {
			t.Fatalf("removal without target observation returned %v", err)
		}
		if _, found := store.Snapshot().Profile(installed[1].ID); !found {
			t.Fatal("unobserved profile was removed")
		}
	})
	t.Run("observation-only backend proves inactive", func(t *testing.T) {
		managed, store, backends, installed := testManager(t, nil)
		backends[profiles.ProtocolWireGuard].availabilityErr = tunnel.ErrUnavailable
		if _, err := managed.Remove(context.Background(), installed[1].ID); err != nil {
			t.Fatalf("inactive removal with observation-only backend: %v", err)
		}
		if _, found := store.Snapshot().Profile(installed[1].ID); found {
			t.Fatal("proved-inactive profile remained")
		}
	})
	t.Run("observation-only backend still blocks active removal", func(t *testing.T) {
		managed, _, backends, installed := testManager(t, nil)
		backends[profiles.ProtocolWireGuard].availabilityErr = tunnel.ErrUnavailable
		backends[profiles.ProtocolWireGuard].active[installed[1].ID] = true
		if _, err := managed.Remove(context.Background(), installed[1].ID); !errors.Is(err, ErrActiveProfile) {
			t.Fatalf("active removal with observation-only backend returned %v", err)
		}
	})
}

func TestStatusPreservesProvedActiveProfileWhenAnotherProtocolIsUnobservable(t *testing.T) {
	managed, _, backends, installed := testManager(t, nil)
	backends[profiles.ProtocolOpenVPN].active[installed[0].ID] = true
	delete(managed.backends, profiles.ProtocolWireGuard)
	status := managed.Status(context.Background())
	if !status.Connected || status.ObservationAvailable || status.Lifecycle != "observation_unavailable" || status.Profile == nil || status.Profile.ID != installed[0].ID {
		t.Fatalf("partial observation status = %+v", status)
	}
}

func TestStartupReconciliationMatrix(t *testing.T) {
	t.Run("manual stays disconnected", func(t *testing.T) {
		manager, _, backends, _ := testManager(t, nil)
		manager.ReconcileStartup(context.Background())
		if len(backends[profiles.ProtocolOpenVPN].starts)+len(backends[profiles.ProtocolWireGuard].starts) != 0 {
			t.Fatal("manual startup started a tunnel")
		}
	})
	t.Run("restore attempts once", func(t *testing.T) {
		manager, store, backends, installed := testManager(t, nil)
		if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetConnection(installed[1].ID, fixedManagerTime.Unix(), false); err != nil {
			t.Fatal(err)
		}
		manager.ReconcileStartup(context.Background())
		if len(backends[profiles.ProtocolWireGuard].starts) != 1 || !manager.Status(context.Background()).Connected {
			t.Fatalf("restore starts=%v status=%+v", backends[profiles.ProtocolWireGuard].starts, manager.Status(context.Background()))
		}
	})
	t.Run("different active profile conflicts", func(t *testing.T) {
		manager, store, backends, installed := testManager(t, nil)
		if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetConnection(installed[1].ID, fixedManagerTime.Unix(), false); err != nil {
			t.Fatal(err)
		}
		backends[profiles.ProtocolOpenVPN].active[installed[0].ID] = true
		manager.ReconcileStartup(context.Background())
		status := manager.Status(context.Background())
		if status.Lifecycle != "state_conflict" || status.Connected || !status.CanDisconnect {
			t.Fatalf("status = %+v", status)
		}
		if len(backends[profiles.ProtocolWireGuard].starts) != 0 {
			t.Fatal("conflicted startup started the desired profile")
		}
	})
	t.Run("failed restore keeps desired", func(t *testing.T) {
		manager, store, backends, installed := testManager(t, nil)
		if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetConnection(installed[1].ID, fixedManagerTime.Unix(), false); err != nil {
			t.Fatal(err)
		}
		backends[profiles.ProtocolWireGuard].startErr[installed[1].ID] = errors.New("failed")
		manager.ReconcileStartup(context.Background())
		assertDesired(t, store, installed[1].ID)
		if manager.Status(context.Background()).Lifecycle != "failed" {
			t.Fatalf("status = %+v", manager.Status(context.Background()))
		}
	})
	t.Run("cleanup uncertainty conflicts", func(t *testing.T) {
		manager, store, backends, installed := testManager(t, nil)
		if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SetConnection(installed[1].ID, fixedManagerTime.Unix(), false); err != nil {
			t.Fatal(err)
		}
		backends[profiles.ProtocolWireGuard].startErr[installed[1].ID] = errors.Join(errors.New("failed"), tunnel.ErrCleanupUnproved)
		manager.ReconcileStartup(context.Background())
		status := manager.Status(context.Background())
		if status.Lifecycle != "state_conflict" || !status.CanDisconnect {
			t.Fatalf("status = %+v", status)
		}
		assertDesired(t, store, installed[1].ID)
	})
}

func TestCorruptDesiredProfileSettlesFailedAndUnavailable(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	target := installed[0]
	if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(target.ID, fixedManagerTime.Unix(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.ObjectPath(target), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	managed.ReconcileStartup(context.Background())
	status := managed.Status(context.Background())
	if status.Lifecycle != "failed" || status.Connected || status.LastError != "The desired profile could not be restored." {
		t.Fatalf("status = %+v", status)
	}
	manifest := store.Snapshot()
	if manifest.DesiredProfile != target.ID || manifest.ConnectedAt != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	profile, err := managed.Profile(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Available || profile.Capabilities["connect"] || profile.UnavailableReason == "" {
		t.Fatalf("profile = %+v", profile)
	}
	if len(backends[profiles.ProtocolOpenVPN].starts) != 0 {
		t.Fatalf("corrupt profile reached backend: %v", backends[profiles.ProtocolOpenVPN].starts)
	}
	if err := managed.Connect(context.Background(), target.ID); err == nil {
		t.Fatal("corrupt profile connected")
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(store.ObjectPath(target)))), ".executions"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("execution residue = %v, %v", entries, err)
	}
}

func TestFailedTargetAndFailedRestorationRemainStickyConflict(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	previous, target := installed[0], installed[1]
	if err := managed.Connect(context.Background(), previous.ID); err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolWireGuard].startErr[target.ID] = errors.New("target failed")
	backends[profiles.ProtocolOpenVPN].startErr[previous.ID] = errors.New("restore failed")
	if err := managed.Connect(context.Background(), target.ID); !errors.Is(err, ErrManagedStateConflict) {
		t.Fatalf("Connect() error = %v", err)
	}
	status := managed.Status(context.Background())
	if status.Lifecycle != "state_conflict" || status.Connected || !status.CanDisconnect {
		t.Fatalf("status = %+v", status)
	}
	manifest := store.Snapshot()
	if manifest.DesiredProfile != previous.ID || manifest.ConnectedAt != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if err := managed.Connect(context.Background(), target.ID); !errors.Is(err, ErrManagedStateConflict) {
		t.Fatalf("connect in conflict = %v", err)
	}
	if _, err := managed.Remove(context.Background(), target.ID); !errors.Is(err, ErrManagedStateConflict) {
		t.Fatalf("remove in conflict = %v", err)
	}
	if err := managed.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := managed.Status(context.Background()); status.Lifecycle != "disconnected" {
		t.Fatalf("settled status = %+v", status)
	}
}

func TestDisconnectRetriesUnsettledBackendCleanup(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	profile := installed[0]
	backend := backends[profiles.ProtocolOpenVPN]
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	executionPath := backend.startPaths[len(backend.startPaths)-1]
	backend.observationErr = errors.Join(tunnel.ErrObservationFailed, errors.New("OpenVPN process is unsettled"))
	backend.shutdownSettles = true
	backend.mu.Unlock()
	backend.emitUnexpectedExit(tunnel.UnexpectedExit{ProfileID: profile.ID, ExecutionPath: executionPath, CleanupProved: false})
	if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" || !status.CanDisconnect {
		t.Fatalf("conflict status = %+v", status)
	}
	if err := managed.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	shutdownCalls := backend.shutdownCalls
	backend.mu.Unlock()
	if shutdownCalls != 1 {
		t.Fatalf("Shutdown() calls = %d", shutdownCalls)
	}
	if status := managed.Status(context.Background()); status.Lifecycle != "disconnected" || status.Connected {
		t.Fatalf("settled status = %+v", status)
	}
	assertDesired(t, store, "")
}

func TestDisconnectKeepsConflictWhenBackendCleanupIsUnproved(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	profile := installed[0]
	backend := backends[profiles.ProtocolOpenVPN]
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	executionPath := backend.startPaths[len(backend.startPaths)-1]
	backend.observationErr = errors.Join(tunnel.ErrObservationFailed, errors.New("OpenVPN process is unsettled"))
	backend.shutdownErr = errors.New("cleanup deadline exceeded")
	backend.mu.Unlock()
	backend.emitUnexpectedExit(tunnel.UnexpectedExit{ProfileID: profile.ID, ExecutionPath: executionPath, CleanupProved: false})
	if err := managed.Disconnect(context.Background()); !errors.Is(err, ErrManagedStateConflict) {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" || !status.CanDisconnect {
		t.Fatalf("conflict status = %+v", status)
	}
	assertDesired(t, store, profile.ID)
}

func TestUnexpectedExitObservationTimeoutReleasesAdmission(t *testing.T) {
	managed, _, backends, installed := testManager(t, nil)
	managed.timeout = 20 * time.Millisecond
	profile := installed[0]
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	openVPN := backends[profiles.ProtocolOpenVPN]
	openVPN.mu.Lock()
	executionPath := openVPN.startPaths[len(openVPN.startPaths)-1]
	openVPN.mu.Unlock()
	wireGuard := backends[profiles.ProtocolWireGuard]
	wireGuard.mu.Lock()
	wireGuard.observeEntered = make(chan struct{}, 1)
	wireGuard.observeRelease = make(chan struct{})
	wireGuard.mu.Unlock()
	done := make(chan struct{})
	go func() {
		openVPN.emitUnexpectedExit(tunnel.UnexpectedExit{ProfileID: profile.ID, ExecutionPath: executionPath, CleanupProved: true})
		close(done)
	}()
	select {
	case <-wireGuard.observeEntered:
	case <-time.After(time.Second):
		t.Fatal("unexpected-exit observation did not reach the blocking backend")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected-exit observation did not respect the manager timeout")
	}
	if status := managed.Status(context.Background()); status.Lifecycle != "state_conflict" || !status.CanDisconnect {
		t.Fatalf("timed-out status = %+v", status)
	}
	wireGuard.mu.Lock()
	close(wireGuard.observeRelease)
	wireGuard.observeRelease = nil
	wireGuard.observeEntered = nil
	wireGuard.mu.Unlock()
	if err := managed.Disconnect(context.Background()); err != nil {
		t.Fatalf("admission remained blocked after observation timeout: %v", err)
	}
}

func TestRecoveryTruthMapping(t *testing.T) {
	injected := errors.New("injected")
	tests := []struct {
		name                                string
		cleanup, restore, repair, reconcile error
		wantTruth                           networkTruth
		wantLifecycle                       string
	}{
		{name: "proved rollback", wantTruth: networkTruthKnown, wantLifecycle: "failed"},
		{name: "target cleanup", cleanup: injected, wantTruth: networkTruthUncertain, wantLifecycle: "state_conflict"},
		{name: "previous restoration", restore: injected, wantTruth: networkTruthUncertain, wantLifecycle: "state_conflict"},
		{name: "durability repair", repair: injected, wantTruth: networkTruthUncertain, wantLifecycle: "state_conflict"},
		{name: "state reconciliation", reconcile: injected, wantTruth: networkTruthUncertain, wantLifecycle: "state_conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			truth := recoveryTruth(test.cleanup, test.restore, test.repair, test.reconcile)
			if truth != test.wantTruth || lifecycleForTruth(truth) != test.wantLifecycle {
				t.Fatalf("truth = %v lifecycle = %q", truth, lifecycleForTruth(truth))
			}
		})
	}
}

func TestUnexpectedOpenVPNExitClearsTimingAndEveryExecutionCopy(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	profile := installed[0]
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	startedPath := backends[profiles.ProtocolOpenVPN].startPaths[0]
	_, extraPath, extraCleanup, err := store.PrepareExecution(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	managed.addExecution(profile.ID, executionCopy{path: extraPath, cleanup: extraCleanup})

	backends[profiles.ProtocolOpenVPN].emitUnexpectedExit(tunnel.UnexpectedExit{
		ProfileID: profile.ID, ExecutionPath: startedPath, CleanupProved: true,
	})
	status := managed.Status(context.Background())
	if status.Lifecycle != "failed" || status.Connected || status.LastError != "The OpenVPN process exited unexpectedly." {
		t.Fatalf("status = %+v", status)
	}
	manifest := store.Snapshot()
	if manifest.DesiredProfile != profile.ID || manifest.ConnectedAt != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	for _, path := range []string{startedPath, extraPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("execution copy %q survived: %v", path, err)
		}
	}
	managed.executionMu.Lock()
	remaining := len(managed.executions[profile.ID])
	managed.executionMu.Unlock()
	if remaining != 0 {
		t.Fatalf("execution handles remaining = %d", remaining)
	}
	backends[profiles.ProtocolOpenVPN].emitUnexpectedExit(tunnel.UnexpectedExit{
		ProfileID: profile.ID, ExecutionPath: startedPath, CleanupProved: true,
	})
	if status := managed.Status(context.Background()); status.Lifecycle != "failed" || status.LastError != "The OpenVPN process exited unexpectedly." {
		t.Fatalf("repeated exit status = %+v", status)
	}
}

func TestStaleUnexpectedExitPreservesSameProfileReconnect(t *testing.T) {
	managed, _, backends, installed := testManager(t, nil)
	profile := installed[0]
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	oldPath := backends[profiles.ProtocolOpenVPN].startPaths[0]
	backends[profiles.ProtocolOpenVPN].mu.Lock()
	delete(backends[profiles.ProtocolOpenVPN].active, profile.ID)
	backends[profiles.ProtocolOpenVPN].mu.Unlock()
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	newPath := backends[profiles.ProtocolOpenVPN].startPaths[1]

	backends[profiles.ProtocolOpenVPN].notifyUnexpectedExit(tunnel.UnexpectedExit{
		ProfileID: profile.ID, ExecutionPath: oldPath, CleanupProved: true,
	})
	status := managed.Status(context.Background())
	if status.Lifecycle != "active" || !status.Connected || status.Profile == nil || status.Profile.ID != profile.ID {
		t.Fatalf("status = %+v", status)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old execution copy survived: %v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new execution copy was removed: %v", err)
	}
}

func TestStaleUnexpectedExitDoesNotPoisonCompletedSwitch(t *testing.T) {
	managed, store, backends, installed := testManager(t, nil)
	previous, target := installed[0], installed[1]
	if err := managed.Connect(context.Background(), previous.ID); err != nil {
		t.Fatal(err)
	}
	oldPath := backends[profiles.ProtocolOpenVPN].startPaths[0]
	release, err := managed.AcquireLibraryOperation()
	if err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolOpenVPN].mu.Lock()
	delete(backends[profiles.ProtocolOpenVPN].active, previous.ID)
	backends[profiles.ProtocolOpenVPN].mu.Unlock()
	done := make(chan struct{})
	go func() {
		managed.handleUnexpectedExit(tunnel.UnexpectedExit{
			ProfileID: previous.ID, ExecutionPath: oldPath, CleanupProved: true,
		})
		close(done)
	}()
	backends[profiles.ProtocolWireGuard].mu.Lock()
	backends[profiles.ProtocolWireGuard].active[target.ID] = true
	backends[profiles.ProtocolWireGuard].mu.Unlock()
	if _, err := store.SetConnection(target.ID, fixedManagerTime.Unix(), false); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stale exit handler did not settle")
	}
	status := managed.Status(context.Background())
	if status.Lifecycle != "active" || !status.Connected || status.Profile == nil || status.Profile.ID != target.ID {
		t.Fatalf("status = %+v", status)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old execution copy survived: %v", err)
	}
}

func TestStartupReconciliationHoldsAdmissionAndStatusDoesNotMutateManifest(t *testing.T) {
	manager, store, backends, installed := testManager(t, nil)
	if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(installed[1].ID, fixedManagerTime.Unix(), false); err != nil {
		t.Fatal(err)
	}
	backends[profiles.ProtocolWireGuard].startEntered = make(chan struct{}, 1)
	backends[profiles.ProtocolWireGuard].startRelease = make(chan struct{})
	done := make(chan struct{})
	go func() {
		manager.ReconcileStartup(context.Background())
		close(done)
	}()
	<-backends[profiles.ProtocolWireGuard].startEntered
	before := store.Snapshot()
	_ = manager.Status(context.Background())
	after := store.Snapshot()
	if before.LibraryRevision != after.LibraryRevision || before.DesiredProfile != after.DesiredProfile {
		t.Fatalf("status polling mutated manifest: before=%+v after=%+v", before, after)
	}
	if err := manager.Connect(context.Background(), installed[0].ID); !errors.Is(err, ErrTransitionInProgress) {
		t.Fatalf("transition during startup returned %v", err)
	}
	close(backends[profiles.ProtocolWireGuard].startRelease)
	<-done
}

func TestDisconnectCleansMultipleManagedTunnels(t *testing.T) {
	manager, store, backends, installed := testManager(t, nil)
	backends[profiles.ProtocolOpenVPN].active[installed[0].ID] = true
	backends[profiles.ProtocolWireGuard].active[installed[1].ID] = true
	if _, err := store.SetConnection(installed[0].ID, fixedManagerTime.Unix(), false); err != nil {
		t.Fatal(err)
	}
	status := manager.Status(context.Background())
	if status.Connected || status.Lifecycle != "state_conflict" || !status.CanDisconnect {
		t.Fatalf("recoverable conflict status = %+v", status)
	}
	if err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(backends[profiles.ProtocolOpenVPN].active) != 0 || len(backends[profiles.ProtocolWireGuard].active) != 0 {
		t.Fatal("conflicting tunnels survived explicit disconnect")
	}
	assertDesired(t, store, "")
}

var fixedManagerTime = time.Date(2026, time.September, 1, 14, 0, 0, 0, time.UTC)

func testManager(t *testing.T, checkpoint func(string) error) (*Manager, *profiles.Store, map[string]*fakeBackend, []profiles.Profile) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := profiles.OpenStore(profiles.StoreOptions{
		Root: root, RequiredUID: os.Getuid(), Now: func() time.Time { return fixedManagerTime }, Checkpoint: checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	openVPNData := []byte("client\ndev tun\nremote vpn.example.test 1194\n")
	wireGuardData := managerWireGuardProfile()
	installed := []profiles.Profile{
		managerProfile(t, profiles.ProtocolOpenVPN, openVPNData, 1, "Office"),
		managerProfile(t, profiles.ProtocolWireGuard, wireGuardData, 2, "Japan"),
	}
	objects := []profiles.NewObject{{Profile: installed[0], Bytes: openVPNData}, {Profile: installed[1], Bytes: wireGuardData}}
	if _, err := store.Publish(0, objects); err != nil {
		t.Fatal(err)
	}
	backends := map[string]*fakeBackend{
		profiles.ProtocolOpenVPN:   newFakeBackend(profiles.ProtocolOpenVPN),
		profiles.ProtocolWireGuard: newFakeBackend(profiles.ProtocolWireGuard),
	}
	manager, err := New(Options{
		Store: store, Backends: map[string]tunnel.Backend{
			profiles.ProtocolOpenVPN: backends[profiles.ProtocolOpenVPN], profiles.ProtocolWireGuard: backends[profiles.ProtocolWireGuard],
		}, Now: func() time.Time { return fixedManagerTime }, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, store, backends, installed
}

func newFakeBackend(protocol string) *fakeBackend {
	return &fakeBackend{
		protocol: protocol, active: make(map[string]bool), startErr: make(map[string]error), stopErr: make(map[string]error),
		activateOnError: make(map[string]bool),
	}
}

func managerProfile(t *testing.T, protocol string, data []byte, seed byte, name string) profiles.Profile {
	t.Helper()
	id, err := profiles.GenerateID(bytes.NewReader(bytes.Repeat([]byte{seed}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := profiles.ValidateImportedProfile(protocol, data)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return profiles.Profile{
		ID: id, Protocol: protocol, DisplayName: name, Group: "Tests", Identifier: profiles.RuntimeIdentifier(id),
		OriginalFilename: name + map[string]string{profiles.ProtocolOpenVPN: ".ovpn", profiles.ProtocolWireGuard: ".conf"}[protocol],
		ImportedAt:       fixedManagerTime, ContentSHA256: hex.EncodeToString(digest[:]), WireGuardPublicKeySHA256: policy.WireGuardPublicKeySHA256,
	}
}

func managerWireGuardProfile() []byte {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	return []byte("[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + publicKey + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n")
}

func assertDesired(t *testing.T, store *profiles.Store, id string) {
	t.Helper()
	manifest := store.Snapshot()
	if manifest.DesiredProfile != id {
		t.Fatalf("desired profile = %q, want %q", manifest.DesiredProfile, id)
	}
}

func TestRuntimeProfileUsesManagedObjectPath(t *testing.T) {
	manager, store, _, installed := testManager(t, nil)
	_ = manager
	runtime := runtimeProfile(store, installed[0])
	if runtime.Path != filepath.Join(store.ObjectPath(installed[0])) {
		t.Fatalf("runtime path = %q", runtime.Path)
	}
}
