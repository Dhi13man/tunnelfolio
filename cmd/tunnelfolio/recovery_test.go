package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/httpapi"
	"github.com/Dhi13man/tunnelfolio/internal/manager"
	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
)

type recoveryBackend struct {
	mu          sync.Mutex
	active      map[string]bool
	exitHandler func(tunnel.UnexpectedExit)
	startPath   string
}

func (b *recoveryBackend) Protocol() string { return profiles.ProtocolOpenVPN }

func (b *recoveryBackend) Available(context.Context) error { return nil }

func (b *recoveryBackend) Observe(_ context.Context, candidates []tunnel.Profile) ([]tunnel.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]tunnel.Observation, 0, 1)
	for _, candidate := range candidates {
		if b.active[candidate.ID] {
			result = append(result, tunnel.Observation{ProfileID: candidate.ID, Protocol: candidate.Protocol, Identifier: candidate.Identifier})
		}
	}
	return result, nil
}

func (b *recoveryBackend) Start(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	b.active[profile.ID] = true
	b.startPath = profile.Path
	b.mu.Unlock()
	return nil
}

func (b *recoveryBackend) Stop(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	delete(b.active, profile.ID)
	b.mu.Unlock()
	return nil
}

func (b *recoveryBackend) Status(context.Context, tunnel.Profile) (tunnel.ProtocolStatus, error) {
	return tunnel.ProtocolStatus{State: "active"}, nil
}

func (b *recoveryBackend) Shutdown(context.Context) error { return nil }

func (b *recoveryBackend) SetUnexpectedExitHandler(handler func(tunnel.UnexpectedExit)) {
	b.mu.Lock()
	b.exitHandler = handler
	b.mu.Unlock()
}

func (b *recoveryBackend) emit(event tunnel.UnexpectedExit) {
	b.mu.Lock()
	delete(b.active, event.ProfileID)
	handler := b.exitHandler
	b.mu.Unlock()
	handler(event)
}

func TestHTTPStartsBeforeCorruptDesiredProfileReconciliation(t *testing.T) {
	_, store, _, profile := recoveryFixture(t)
	if _, err := store.SetPreferences(nil, nil, profiles.StartupRestore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(profile.ID, time.Now().Unix(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.ObjectPath(profile), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(store.ObjectPath(profile)))))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := profiles.OpenStore(profiles.StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatalf("OpenStore() rejected the corrupt referenced object: %v", err)
	}
	store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	backend := &recoveryBackend{active: make(map[string]bool)}
	managed, err := manager.New(manager.Options{
		Store: store, Backends: map[string]tunnel.Backend{profiles.ProtocolOpenVPN: backend}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := recoveryHTTPServer(t, managed)

	var listed []manager.ProfileView
	recoveryGET(t, server.URL+"/api/profiles", http.StatusOK, &listed)
	if len(listed) != 1 || listed[0].ID != profile.ID || listed[0].Available || listed[0].Capabilities["connect"] {
		t.Fatalf("profiles = %+v", listed)
	}
	managed.ReconcileStartup(context.Background())
	var status manager.Status
	recoveryGET(t, server.URL+"/api/status", http.StatusOK, &status)
	if status.Lifecycle != "failed" || status.Connected || status.LastError != "The desired profile could not be restored." {
		t.Fatalf("status = %+v", status)
	}
	manifest := store.Snapshot()
	if manifest.DesiredProfile != profile.ID || manifest.ConnectedAt != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestUnexpectedOpenVPNExitReachesHTTPStatus(t *testing.T) {
	managed, store, backend, profile := recoveryFixture(t)
	if err := managed.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	managedExecution := backend.startPath
	backend.mu.Unlock()
	server := recoveryHTTPServer(t, managed)

	backend.emit(tunnel.UnexpectedExit{ProfileID: profile.ID, ExecutionPath: managedExecution, CleanupProved: true})
	var status manager.Status
	recoveryGET(t, server.URL+"/api/status", http.StatusOK, &status)
	if status.Lifecycle != "failed" || status.Connected || status.LastError != "The OpenVPN process exited unexpectedly." {
		t.Fatalf("status = %+v", status)
	}
	if manifest := store.Snapshot(); manifest.DesiredProfile != profile.ID || manifest.ConnectedAt != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(managedExecution); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("execution copy survived: %v", err)
	}
}

func recoveryFixture(t *testing.T) (*manager.Manager, *profiles.Store, *recoveryBackend, profiles.Profile) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := profiles.OpenStore(profiles.StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	data := []byte("client\ndev tun\nremote vpn.example.test 1194\n")
	id, err := profiles.GenerateID(bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	profile := profiles.Profile{
		ID: id, Protocol: profiles.ProtocolOpenVPN, DisplayName: "Office", Group: "Tests",
		Identifier: profiles.RuntimeIdentifier(id), OriginalFilename: "office.ovpn", ImportedAt: time.Now().UTC(),
		ContentSHA256: hex.EncodeToString(digest[:]),
	}
	if _, err := store.Publish(0, []profiles.NewObject{{Profile: profile, Bytes: data}}); err != nil {
		t.Fatal(err)
	}
	backend := &recoveryBackend{active: make(map[string]bool)}
	managed, err := manager.New(manager.Options{
		Store: store, Backends: map[string]tunnel.Backend{profiles.ProtocolOpenVPN: backend}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return managed, store, backend, profile
}

func recoveryHTTPServer(t *testing.T, managed *manager.Manager) *httptest.Server {
	t.Helper()
	handler, err := httpapi.New(httpapi.Options{Manager: managed, RuntimeDir: t.TempDir(), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func recoveryGET(t *testing.T, url string, wantStatus int, target any) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		t.Fatalf("GET %s status = %d", url, response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}
