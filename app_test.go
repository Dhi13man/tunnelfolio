package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

const testProxyToken = "tunnelfolio-test-proxy-token-value"

type fakeBackend struct {
	kind string

	mu               sync.Mutex
	active           *CatalogProfile
	additionalActive []CatalogProfile
	availabilityErr  error
	observeErr       error
	startErr         error
	stopErr          error
	startErrors      map[string][]error
	stopErrors       map[string][]error
	activateOnError  map[string]bool
	startEntered     chan struct{}
	startRelease     chan struct{}
	stopEntered      chan struct{}
	stopRelease      chan struct{}
	starts           []string
	stops            []string
}

func (b *fakeBackend) Kind() string  { return b.kind }
func (b *fakeBackend) Enabled() bool { return true }

func (b *fakeBackend) Availability(context.Context) error { return b.availabilityErr }

func (b *fakeBackend) Observe(context.Context) ([]CatalogProfile, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.observeErr != nil {
		return nil, b.observeErr
	}
	if b.active == nil {
		return append([]CatalogProfile(nil), b.additionalActive...), nil
	}
	profile := *b.active
	return append([]CatalogProfile{profile}, b.additionalActive...), nil
}

func (b *fakeBackend) Start(ctx context.Context, profile CatalogProfile) error {
	if b.startEntered != nil {
		select {
		case b.startEntered <- struct{}{}:
		default:
		}
	}
	if b.startRelease != nil {
		select {
		case <-b.startRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starts = append(b.starts, profile.ID)
	err := b.startErr
	if queued := b.startErrors[profile.ID]; len(queued) > 0 {
		err = queued[0]
		b.startErrors[profile.ID] = queued[1:]
	}
	if err != nil {
		if b.activateOnError[profile.ID] {
			copy := profile
			b.active = &copy
		}
		return err
	}
	copy := profile
	b.active = &copy
	return nil
}

func (b *fakeBackend) Stop(ctx context.Context, profile CatalogProfile) error {
	if b.stopEntered != nil {
		select {
		case b.stopEntered <- struct{}{}:
		default:
		}
	}
	if b.stopRelease != nil {
		select {
		case <-b.stopRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stops = append(b.stops, profile.ID)
	err := b.stopErr
	if queued := b.stopErrors[profile.ID]; len(queued) > 0 {
		err = queued[0]
		b.stopErrors[profile.ID] = queued[1:]
	}
	if err != nil {
		return err
	}
	if b.active != nil && b.active.ID == profile.ID {
		b.active = nil
	}
	remaining := b.additionalActive[:0]
	for _, candidate := range b.additionalActive {
		if candidate.ID != profile.ID {
			remaining = append(remaining, candidate)
		}
	}
	b.additionalActive = remaining
	return nil
}

func (b *fakeBackend) Metrics(context.Context, CatalogProfile) (backendMetrics, error) {
	return backendMetrics{"received_bytes": uint64(12), "sent_bytes": uint64(34)}, nil
}

func (b *fakeBackend) Shutdown(context.Context) error { return nil }

func testApp(t *testing.T) (*Server, http.Handler, map[string]*fakeBackend, map[string]CatalogProfile) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "profiles")
	for _, directory := range []string{
		root,
		filepath.Join(root, BackendOpenVPN),
		filepath.Join(root, BackendOpenVPN, "generic"),
		filepath.Join(root, BackendOpenVPN, "mullvad"),
		filepath.Join(root, BackendWireGuard),
		filepath.Join(root, BackendWireGuard, "mullvad"),
		filepath.Join(root, BackendWireGuard, "generic"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(root, BackendOpenVPN, "generic", "office.ovpn"):       "client\n",
		filepath.Join(root, BackendOpenVPN, "mullvad", "mullvad_us.ovpn"):   "client\n",
		filepath.Join(root, BackendWireGuard, "mullvad", "mullvad_de.conf"): "[Interface]\n",
		filepath.Join(root, BackendWireGuard, "generic", "home.conf"):       "[Interface]\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := newProfileCatalog(root, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	profiles := make(map[string]CatalogProfile)
	for _, kind := range []string{BackendOpenVPN, BackendWireGuard} {
		entries, listErr := catalog.Profiles(kind)
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, profile := range entries {
			profiles[profile.ID] = profile
		}
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "proxy-token")
	if err := os.WriteFile(tokenPath, []byte(testProxyToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakes := map[string]*fakeBackend{
		BackendOpenVPN:   {kind: BackendOpenVPN, startErrors: make(map[string][]error), stopErrors: make(map[string][]error), activateOnError: make(map[string]bool)},
		BackendWireGuard: {kind: BackendWireGuard, startErrors: make(map[string][]error), stopErrors: make(map[string][]error), activateOnError: make(map[string]bool)},
	}
	backends := map[string]managedBackend{BackendOpenVPN: fakes[BackendOpenVPN], BackendWireGuard: fakes[BackendWireGuard]}
	server, err := NewServer(options{profilesDir: root, stateDir: stateDir, trustedProxy: true, proxyTokenFile: tokenPath}, catalog, backends)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(server)
	if err != nil {
		t.Fatal(err)
	}
	return server, router, fakes, profiles
}

func request(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyTokenHeader, testProxyToken)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "vpn.example.test")
	req.Header.Set("X-Remote-User", "operator")
	if method != http.MethodGet {
		req.Header.Set("Origin", "https://vpn.example.test")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func rawRequest(handler http.Handler, method, path, body, contentType string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set(proxyTokenHeader, testProxyToken)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "vpn.example.test")
	req.Header.Set("X-Remote-User", "operator")
	if method != http.MethodGet {
		req.Header.Set("Origin", "https://vpn.example.test")
	}
	if mutate != nil {
		mutate(req)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestAuditOperationForRequestUsesMutationRoute(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodPost, path: "/api/connect", want: "connect"},
		{method: http.MethodPost, path: "/api/disconnect", want: "disconnect"},
		{method: http.MethodPut, path: "/api/preferences", want: "preferences"},
		{method: http.MethodGet, path: "/api/status", want: "authentication"},
		{method: http.MethodGet, path: "/api/connect", want: "authentication"},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if got := auditOperationForRequest(request); got != test.want {
				t.Fatalf("audit operation = %q, want %q", got, test.want)
			}
		})
	}
}

func setConnected(t *testing.T, server *Server, backend *fakeBackend, profile CatalogProfile, connectedAt int64) {
	t.Helper()
	backend.mu.Lock()
	copy := profile
	backend.active = &copy
	backend.mu.Unlock()
	config := Config{Version: stateVersion, ActiveProfile: profile.ID, ConnectedAt: connectedAt}
	if _, err := writeJSONAtomic(server.configPath, config); err != nil {
		t.Fatal(err)
	}
	server.stateMu.Lock()
	server.config = config
	server.stateMu.Unlock()
}

func readConfigFile(t *testing.T, server *Server) Config {
	t.Helper()
	var config Config
	if err := readJSON(server.configPath, &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func responseCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, response.Body.String())
	}
	return payload.Code
}

func TestParseOptionsRequiresAuthenticationForMutation(t *testing.T) {
	if _, err := parseOptions([]string{"--read-only"}); err != nil {
		t.Fatalf("read-only loopback should be accepted: %v", err)
	}
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("mutable unauthenticated startup should fail")
	}
	if err := validateListenAddress("0.0.0.0:50001"); err == nil {
		t.Fatal("non-loopback listener should fail")
	}
}

func TestProfilesAndBackendNeutralStatus(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	response := request(t, handler, http.MethodGet, "/api/profiles", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("profiles status=%d body=%s", response.Code, response.Body.String())
	}
	var listed []profileResponse
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 4 {
		t.Fatalf("expected both backends, got %#v", listed)
	}
	active := profiles["wireguard/mullvad/mullvad_de"]
	backends[BackendWireGuard].active = &active
	server.config = Config{Version: stateVersion, ActiveProfile: active.ID, ConnectedAt: time.Now().Add(-time.Minute).Unix()}
	response = request(t, handler, http.MethodGet, "/api/status", nil)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"backend":"wireguard"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCrossBackendSwitchPersistsOnlyAfterReadiness(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	backends[BackendWireGuard].active = &old
	server.config = Config{Version: stateVersion, ActiveProfile: old.ID, ConnectedAt: 1}
	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
	if response.Code != http.StatusOK {
		t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
	}
	if got := server.snapshotConfig().ActiveProfile; got != "openvpn/generic/office" {
		t.Fatalf("active state=%q", got)
	}
	if len(backends[BackendWireGuard].stops) != 1 || len(backends[BackendOpenVPN].starts) != 1 {
		t.Fatalf("unexpected transition wg stops=%v ovpn starts=%v", backends[BackendWireGuard].stops, backends[BackendOpenVPN].starts)
	}
}

func TestFailedCrossBackendSwitchRestoresOldProfile(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	backends[BackendWireGuard].active = &old
	backends[BackendOpenVPN].startErr = errors.New("readiness failed")
	server.config = Config{Version: stateVersion, ActiveProfile: old.ID, ConnectedAt: 1}
	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
	if response.Code != http.StatusBadGateway || !bytes.Contains(response.Body.Bytes(), []byte("previous profile was restored")) {
		t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backends[BackendWireGuard].starts) != 1 || backends[BackendWireGuard].active == nil {
		t.Fatalf("old profile was not restored: starts=%v active=%v", backends[BackendWireGuard].starts, backends[BackendWireGuard].active)
	}
	if got := server.snapshotConfig().ActiveProfile; got != old.ID {
		t.Fatalf("persisted state changed on failed switch: %q", got)
	}
}

func TestOldStopFailureAbortsBeforeNewStart(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	backends[BackendWireGuard].active = &old
	backends[BackendWireGuard].stopErr = errors.New("interface still present")
	server.config = Config{Version: stateVersion, ActiveProfile: old.ID}
	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backends[BackendOpenVPN].starts) != 0 {
		t.Fatalf("target started after uncertain stop: %v", backends[BackendOpenVPN].starts)
	}
}

func TestTransitionAdmissionHasNoQueue(t *testing.T) {
	_, handler, backends, _ := testApp(t)
	backends[BackendOpenVPN].startEntered = make(chan struct{}, 1)
	backends[BackendOpenVPN].startRelease = make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
	}()
	select {
	case <-backends[BackendOpenVPN].startEntered:
	case <-time.After(time.Second):
		t.Fatal("first transition did not enter backend")
	}
	second := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if second.Code != http.StatusConflict || !bytes.Contains(second.Body.Bytes(), []byte("transition_in_progress")) {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	close(backends[BackendOpenVPN].startRelease)
	if first := <-done; first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
}

func TestZeroBackendHealthIsLiveAndDegraded(t *testing.T) {
	_, handler, backends, _ := testApp(t)
	backends[BackendOpenVPN].availabilityErr = errors.New("missing")
	backends[BackendWireGuard].availabilityErr = errors.New("missing")
	response := request(t, handler, http.MethodGet, "/healthz", nil)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"readiness":"degraded"`)) {
		t.Fatalf("health status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestProxyAndSecurityHeaders(t *testing.T) {
	_, handler, _, _ := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", response.Code)
	}
	authorized := request(t, handler, http.MethodGet, "/", nil)
	if csp := authorized.Header().Get("Content-Security-Policy"); csp == "" || bytes.Contains([]byte(csp), []byte("unsafe-inline")) {
		t.Fatalf("unexpected CSP %q", csp)
	}
	if authorized.Header().Get("X-Request-ID") == "" {
		t.Fatal("request ID missing")
	}
}

func TestPreferencesRequireCatalogIDs(t *testing.T) {
	_, handler, _, _ := testApp(t)
	valid := Preferences{Favorites: []string{"openvpn/generic/office"}, Recents: []string{"wireguard/mullvad/mullvad_de"}}
	response := request(t, handler, http.MethodPut, "/api/preferences", valid)
	if response.Code != http.StatusOK {
		t.Fatalf("valid status=%d body=%s", response.Code, response.Body.String())
	}
	invalid := Preferences{Favorites: []string{"mullvad_de"}}
	response = request(t, handler, http.MethodPut, "/api/preferences", invalid)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectSwitchAndDisconnectMatrix(t *testing.T) {
	tests := []struct {
		name  string
		oldID string
		newID string
	}{
		{name: "initial OpenVPN connect", newID: "openvpn/generic/office"},
		{name: "initial WireGuard connect", newID: "wireguard/mullvad/mullvad_de"},
		{name: "WireGuard to OpenVPN", oldID: "wireguard/mullvad/mullvad_de", newID: "openvpn/generic/office"},
		{name: "OpenVPN to WireGuard", oldID: "openvpn/generic/office", newID: "wireguard/mullvad/mullvad_de"},
		{name: "within OpenVPN", oldID: "openvpn/generic/office", newID: "openvpn/mullvad/mullvad_us"},
		{name: "within WireGuard", oldID: "wireguard/mullvad/mullvad_de", newID: "wireguard/generic/home"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, handler, backends, profiles := testApp(t)
			if tc.oldID != "" {
				old := profiles[tc.oldID]
				setConnected(t, server, backends[old.Backend], old, 123)
			}
			response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": tc.newID})
			if response.Code != http.StatusOK {
				t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
			}
			if got := readConfigFile(t, server).ActiveProfile; got != tc.newID {
				t.Fatalf("durable active profile=%q, want %q", got, tc.newID)
			}
			status := request(t, handler, http.MethodGet, "/api/status", nil)
			if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"id":"`+tc.newID+`"`)) {
				t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
			}
			response = request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
			if response.Code != http.StatusOK {
				t.Fatalf("disconnect status=%d body=%s", response.Code, response.Body.String())
			}
			if got := readConfigFile(t, server); got.ActiveProfile != "" || got.ConnectedAt != 0 {
				t.Fatalf("durable state after disconnect=%#v", got)
			}
			status = request(t, handler, http.MethodGet, "/api/status", nil)
			if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"connected":false`)) {
				t.Fatalf("disconnected status=%d body=%s", status.Code, status.Body.String())
			}
		})
	}
}

func TestConnectAndDisconnectAreIdempotent(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	active := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendOpenVPN], active, 123)
	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": active.ID})
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("Already connected")) {
		t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backends[BackendOpenVPN].starts) != 0 || len(backends[BackendOpenVPN].stops) != 0 {
		t.Fatalf("idempotent connect changed backend: starts=%v stops=%v", backends[BackendOpenVPN].starts, backends[BackendOpenVPN].stops)
	}
	if got := readConfigFile(t, server); got.ActiveProfile != active.ID || got.ConnectedAt != 123 {
		t.Fatalf("idempotent connect changed durable state: %#v", got)
	}
	response = request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if response.Code != http.StatusOK {
		t.Fatalf("first disconnect status=%d body=%s", response.Code, response.Body.String())
	}
	stops := len(backends[BackendOpenVPN].stops)
	response = request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("Already disconnected")) {
		t.Fatalf("second disconnect status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backends[BackendOpenVPN].stops) != stops {
		t.Fatalf("idempotent disconnect stopped backend again: %v", backends[BackendOpenVPN].stops)
	}
}

func TestFailedTargetIsCleanedBeforeRestoration(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	target := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendWireGuard], old, 123)
	backends[BackendOpenVPN].startErrors[target.ID] = []error{errors.New("readiness timeout")}
	backends[BackendOpenVPN].activateOnError[target.ID] = true
	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
	if response.Code != http.StatusBadGateway || responseCode(t, response) != "connect_failed" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backends[BackendOpenVPN].stops) != 1 || backends[BackendOpenVPN].active != nil {
		t.Fatalf("partial target was not cleaned: stops=%v active=%v", backends[BackendOpenVPN].stops, backends[BackendOpenVPN].active)
	}
	if backends[BackendWireGuard].active == nil || readConfigFile(t, server).ActiveProfile != old.ID {
		t.Fatal("old connection and durable state were not restored")
	}
}

func TestFailureRecoveryRunsInBothCrossBackendDirections(t *testing.T) {
	tests := []struct {
		name     string
		oldID    string
		targetID string
	}{
		{name: "WireGuard to OpenVPN", oldID: "wireguard/mullvad/mullvad_de", targetID: "openvpn/generic/office"},
		{name: "OpenVPN to WireGuard", oldID: "openvpn/generic/office", targetID: "wireguard/mullvad/mullvad_de"},
	}
	for _, tc := range tests {
		t.Run(tc.name+" restores", func(t *testing.T) {
			server, handler, backends, profiles := testApp(t)
			old, target := profiles[tc.oldID], profiles[tc.targetID]
			setConnected(t, server, backends[old.Backend], old, 123)
			backends[target.Backend].startErrors[target.ID] = []error{errors.New("not ready")}
			response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
			if response.Code != http.StatusBadGateway || responseCode(t, response) != "connect_failed" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if backends[old.Backend].active == nil || backends[target.Backend].active != nil || readConfigFile(t, server).ActiveProfile != old.ID {
				t.Fatal("old network and durable state were not restored")
			}
		})

		t.Run(tc.name+" restoration fails closed", func(t *testing.T) {
			server, handler, backends, profiles := testApp(t)
			old, target := profiles[tc.oldID], profiles[tc.targetID]
			setConnected(t, server, backends[old.Backend], old, 123)
			backends[target.Backend].startErrors[target.ID] = []error{errors.New("not ready")}
			backends[old.Backend].startErrors[old.ID] = []error{errors.New("restore failed")}
			response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
			if response.Code != http.StatusBadGateway || responseCode(t, response) != "switch_and_rollback_failed" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if got := readConfigFile(t, server).ActiveProfile; got != "" {
				t.Fatalf("uncertain state remained durably claimed as %q", got)
			}
		})
	}
}

func TestTransitionFaultMatrixAcrossBackends(t *testing.T) {
	transitions := []struct {
		name     string
		oldID    string
		targetID string
	}{
		{name: "none to OpenVPN", targetID: "openvpn/generic/office"},
		{name: "none to WireGuard", targetID: "wireguard/mullvad/mullvad_de"},
		{name: "OpenVPN to OpenVPN", oldID: "openvpn/generic/office", targetID: "openvpn/mullvad/mullvad_us"},
		{name: "WireGuard to WireGuard", oldID: "wireguard/mullvad/mullvad_de", targetID: "wireguard/generic/home"},
		{name: "OpenVPN to WireGuard", oldID: "openvpn/generic/office", targetID: "wireguard/mullvad/mullvad_de"},
		{name: "WireGuard to OpenVPN", oldID: "wireguard/mullvad/mullvad_de", targetID: "openvpn/generic/office"},
	}
	for _, transition := range transitions {
		transition := transition
		t.Run(transition.name, func(t *testing.T) {
			setup := func(t *testing.T) (*Server, http.Handler, map[string]*fakeBackend, map[string]CatalogProfile, *CatalogProfile, CatalogProfile) {
				t.Helper()
				server, handler, backends, profiles := testApp(t)
				var old *CatalogProfile
				if transition.oldID != "" {
					profile := profiles[transition.oldID]
					old = &profile
					setConnected(t, server, backends[profile.Backend], profile, 123)
				}
				return server, handler, backends, profiles, old, profiles[transition.targetID]
			}
			assertRestored := func(t *testing.T, server *Server, backends map[string]*fakeBackend, old *CatalogProfile, target CatalogProfile) {
				t.Helper()
				if backends[target.Backend].active != nil && backends[target.Backend].active.ID == target.ID {
					t.Fatalf("target %s remained active", target.ID)
				}
				config := readConfigFile(t, server)
				if old == nil {
					if config.ActiveProfile != "" {
						t.Fatalf("failed initial transition persisted %q", config.ActiveProfile)
					}
					return
				}
				if backends[old.Backend].active == nil || backends[old.Backend].active.ID != old.ID {
					t.Fatalf("old profile %s was not restored", old.ID)
				}
				if config.ActiveProfile != old.ID || config.ConnectedAt != 123 {
					t.Fatalf("restored durable state = %#v, want %s at 123", config, old.ID)
				}
			}

			for _, failure := range []struct {
				name string
				err  error
			}{
				{name: "new start failure", err: errors.New("not ready")},
				{name: "readiness timeout", err: context.DeadlineExceeded},
				{name: "cancellation", err: context.Canceled},
			} {
				failure := failure
				t.Run(failure.name, func(t *testing.T) {
					server, handler, backends, _, old, target := setup(t)
					backends[target.Backend].startErrors[target.ID] = []error{failure.err}
					backends[target.Backend].activateOnError[target.ID] = true
					response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
					if response.Code != http.StatusBadGateway || responseCode(t, response) != "connect_failed" {
						t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
					}
					if len(backends[target.Backend].stops) == 0 || backends[target.Backend].stops[len(backends[target.Backend].stops)-1] != target.ID {
						t.Fatalf("target cleanup calls = %v", backends[target.Backend].stops)
					}
					assertRestored(t, server, backends, old, target)
				})
			}

			t.Run("persistence failure", func(t *testing.T) {
				server, handler, backends, _, old, target := setup(t)
				writes := 0
				server.writeState = func(path string, value any) (stateWriteResult, error) {
					if path == server.configPath {
						writes++
						if writes == 1 {
							return stateWriteResult{}, errors.New("disk full")
						}
					}
					return writeJSONAtomic(path, value)
				}
				response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
				if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_failed" {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				assertRestored(t, server, backends, old, target)
			})

			if transition.oldID != "" {
				t.Run("old stop failure", func(t *testing.T) {
					server, handler, backends, _, old, target := setup(t)
					backends[old.Backend].stopErrors[old.ID] = []error{errors.New("still active")}
					response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
					if response.Code != http.StatusBadGateway || responseCode(t, response) != "disconnect_failed" {
						t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
					}
					if slices.Contains(backends[target.Backend].starts, target.ID) {
						t.Fatalf("target started after old-stop failure: %v", backends[target.Backend].starts)
					}
					if got := readConfigFile(t, server); got.ActiveProfile != old.ID || got.ConnectedAt != 123 {
						t.Fatalf("durable state changed: %#v", got)
					}
				})

				t.Run("restoration failure", func(t *testing.T) {
					server, handler, backends, _, old, target := setup(t)
					backends[target.Backend].startErrors[target.ID] = []error{errors.New("not ready")}
					backends[old.Backend].startErrors[old.ID] = []error{errors.New("restore failed")}
					response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
					if response.Code != http.StatusBadGateway || responseCode(t, response) != "switch_and_rollback_failed" {
						t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
					}
					if got := readConfigFile(t, server); got.ActiveProfile != "" || got.ConnectedAt != 0 {
						t.Fatalf("uncertain restoration retained durable claim: %#v", got)
					}
				})
			}

			t.Run("restart reconciliation", func(t *testing.T) {
				server, handler, backends, _, _, target := setup(t)
				response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
				if response.Code != http.StatusOK {
					t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
				}
				tokenPath := filepath.Join(t.TempDir(), "proxy-token")
				if err := os.WriteFile(tokenPath, []byte(testProxyToken+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				restarted, err := NewServer(options{stateDir: filepath.Dir(server.configPath), trustedProxy: true, proxyTokenFile: tokenPath}, server.catalog, map[string]managedBackend{
					BackendOpenVPN: backends[BackendOpenVPN], BackendWireGuard: backends[BackendWireGuard],
				})
				if err != nil {
					t.Fatal(err)
				}
				router, err := newRouter(restarted)
				if err != nil {
					t.Fatal(err)
				}
				status := request(t, router, http.MethodGet, "/api/status", nil)
				if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"id":"`+target.ID+`"`)) {
					t.Fatalf("restart status=%d body=%s", status.Code, status.Body.String())
				}
			})
		})
	}
}

func TestDisconnectFaultMatrixAcrossBackends(t *testing.T) {
	for _, activeID := range []string{"openvpn/generic/office", "wireguard/mullvad/mullvad_de"} {
		activeID := activeID
		t.Run(activeID, func(t *testing.T) {
			t.Run("stop failure", func(t *testing.T) {
				server, handler, backends, profiles := testApp(t)
				active := profiles[activeID]
				setConnected(t, server, backends[active.Backend], active, 123)
				backends[active.Backend].stopErrors[active.ID] = []error{errors.New("still active")}
				response := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
				if response.Code != http.StatusBadGateway || responseCode(t, response) != "disconnect_failed" {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				if got := readConfigFile(t, server); got.ActiveProfile != active.ID || got.ConnectedAt != 123 {
					t.Fatalf("durable state changed: %#v", got)
				}
			})

			t.Run("persistence failure restores network", func(t *testing.T) {
				server, handler, backends, profiles := testApp(t)
				active := profiles[activeID]
				setConnected(t, server, backends[active.Backend], active, 123)
				writes := 0
				server.writeState = func(path string, value any) (stateWriteResult, error) {
					if path == server.configPath {
						writes++
						if writes == 1 {
							return stateWriteResult{}, errors.New("disk full")
						}
					}
					return writeJSONAtomic(path, value)
				}
				response := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
				if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_failed" {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				if backends[active.Backend].active == nil || backends[active.Backend].active.ID != active.ID {
					t.Fatalf("active network was not restored: %+v", backends[active.Backend].active)
				}
				if got := readConfigFile(t, server); got.ActiveProfile != active.ID || got.ConnectedAt != 123 {
					t.Fatalf("durable state was not restored: %#v", got)
				}
			})
		})
	}
}

func TestInitialConnectFailureLeavesNoClaimedConnection(t *testing.T) {
	for _, targetID := range []string{"openvpn/generic/office", "wireguard/mullvad/mullvad_de"} {
		t.Run(targetID, func(t *testing.T) {
			server, handler, backends, profiles := testApp(t)
			target := profiles[targetID]
			backends[target.Backend].startErrors[target.ID] = []error{errors.New("not ready")}
			backends[target.Backend].activateOnError[target.ID] = true
			response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
			if response.Code != http.StatusBadGateway || responseCode(t, response) != "connect_failed" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if backends[target.Backend].active != nil {
				t.Fatal("partially active initial target was not cleaned")
			}
			if got := readConfigFile(t, server).ActiveProfile; got != "" {
				t.Fatalf("failed initial connection persisted %q", got)
			}
			status := request(t, handler, http.MethodGet, "/api/status", nil)
			if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"connected":false`)) || !bytes.Contains(status.Body.Bytes(), []byte(`"last_error":"profile could not be connected"`)) {
				t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
			}
		})
	}
}

func TestCanceledConnectCleansTargetAndRestoresOldProfile(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	setConnected(t, server, backends[BackendWireGuard], old, 123)
	backends[BackendOpenVPN].startEntered = make(chan struct{}, 1)
	backends[BackendOpenVPN].startRelease = make(chan struct{})
	req := httptest.NewRequest(http.MethodPost, "/api/connect", bytes.NewBufferString(`{"profile":"openvpn/generic/office"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyTokenHeader, testProxyToken)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "vpn.example.test")
	req.Header.Set("X-Remote-User", "operator")
	req.Header.Set("Origin", "https://vpn.example.test")
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		done <- response
	}()
	<-backends[BackendOpenVPN].startEntered
	cancel()
	response := <-done
	if response.Code != http.StatusBadGateway || responseCode(t, response) != "connect_failed" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if backends[BackendOpenVPN].active != nil || backends[BackendWireGuard].active == nil || readConfigFile(t, server).ActiveProfile != old.ID {
		t.Fatal("canceled transition did not clean target and restore old profile")
	}
}

func TestTransitionFailureClassesPreserveHonestState(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*Server, map[string]*fakeBackend, map[string]CatalogProfile)
		wantCode   string
		wantStatus int
		wantDisk   string
	}{
		{
			name: "old stop failure",
			configure: func(_ *Server, b map[string]*fakeBackend, p map[string]CatalogProfile) {
				b[BackendWireGuard].stopErrors[p["wireguard/mullvad/mullvad_de"].ID] = []error{errors.New("still active")}
			},
			wantCode: "disconnect_failed", wantStatus: http.StatusBadGateway, wantDisk: "wireguard/mullvad/mullvad_de",
		},
		{
			name: "target cleanup failure",
			configure: func(_ *Server, b map[string]*fakeBackend, p map[string]CatalogProfile) {
				target := p["openvpn/generic/office"]
				b[BackendOpenVPN].startErrors[target.ID] = []error{errors.New("not ready")}
				b[BackendOpenVPN].stopErrors[target.ID] = []error{errors.New("process remains")}
			},
			wantCode: "connect_cleanup_failed", wantStatus: http.StatusBadGateway, wantDisk: "",
		},
		{
			name: "restoration failure",
			configure: func(_ *Server, b map[string]*fakeBackend, p map[string]CatalogProfile) {
				target := p["openvpn/generic/office"]
				old := p["wireguard/mullvad/mullvad_de"]
				b[BackendOpenVPN].startErrors[target.ID] = []error{errors.New("not ready")}
				b[BackendWireGuard].startErrors[old.ID] = []error{errors.New("restore failed")}
			},
			wantCode: "switch_and_rollback_failed", wantStatus: http.StatusBadGateway, wantDisk: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, handler, backends, profiles := testApp(t)
			old := profiles["wireguard/mullvad/mullvad_de"]
			setConnected(t, server, backends[BackendWireGuard], old, 123)
			tc.configure(server, backends, profiles)
			response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
			if response.Code != tc.wantStatus || responseCode(t, response) != tc.wantCode {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if got := readConfigFile(t, server).ActiveProfile; got != tc.wantDisk {
				t.Fatalf("durable active profile=%q, want %q", got, tc.wantDisk)
			}
		})
	}
}

func TestPersistenceFailureCompensatesNetworkState(t *testing.T) {
	t.Run("connect restores old profile", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		old := profiles["wireguard/mullvad/mullvad_de"]
		setConnected(t, server, backends[BackendWireGuard], old, 123)
		configCalls := 0
		server.writeState = func(path string, value any) (stateWriteResult, error) {
			if path == server.configPath {
				configCalls++
				if configCalls == 1 {
					return stateWriteResult{}, errors.New("disk full")
				}
			}
			return writeJSONAtomic(path, value)
		}
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_failed" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if backends[BackendWireGuard].active == nil || backends[BackendOpenVPN].active != nil {
			t.Fatalf("network was not compensated: wg=%v ovpn=%v", backends[BackendWireGuard].active, backends[BackendOpenVPN].active)
		}
		if got := readConfigFile(t, server); got.ActiveProfile != old.ID || got.ConnectedAt != 123 {
			t.Fatalf("durable state changed: %#v", got)
		}
	})

	t.Run("disconnect restores active profile", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		active := profiles["openvpn/generic/office"]
		setConnected(t, server, backends[BackendOpenVPN], active, 123)
		configCalls := 0
		server.writeState = func(path string, value any) (stateWriteResult, error) {
			configCalls++
			if configCalls == 1 {
				return stateWriteResult{}, errors.New("disk full")
			}
			return writeJSONAtomic(path, value)
		}
		response := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
		if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_failed" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if backends[BackendOpenVPN].active == nil || readConfigFile(t, server).ActiveProfile != active.ID {
			t.Fatal("disconnect persistence failure did not restore network and disk state")
		}
	})

	t.Run("compensation failure clears claimed durable state", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		old := profiles["wireguard/mullvad/mullvad_de"]
		setConnected(t, server, backends[BackendWireGuard], old, 123)
		calls := 0
		server.writeState = func(path string, value any) (stateWriteResult, error) {
			if path != server.configPath {
				return writeJSONAtomic(path, value)
			}
			calls++
			if calls == 1 {
				return stateWriteResult{}, errors.New("disk full")
			}
			return writeJSONAtomic(path, value)
		}
		backends[BackendOpenVPN].stopErrors["openvpn/generic/office"] = []error{errors.New("target remains active")}
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_and_rollback_failed" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if got := readConfigFile(t, server).ActiveProfile; got != "" {
			t.Fatalf("uncertain network state remained durably claimed as %q", got)
		}
	})
}

func TestPublishedButUnsyncedStateIsReplacedAfterCompensation(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	setConnected(t, server, backends[BackendWireGuard], old, 123)
	calls := 0
	server.writeState = func(path string, value any) (stateWriteResult, error) {
		result, err := writeJSONAtomic(path, value)
		if err != nil {
			return result, err
		}
		if path == server.configPath {
			calls++
			if calls == 1 {
				return stateWriteResult{Published: true}, errors.New("directory sync failed")
			}
		}
		return result, nil
	}

	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
	if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_save_failed" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if calls != 2 {
		t.Fatalf("config writes = %d, want failed publication plus deliberate restoration", calls)
	}
	var restarted Config
	if err := readJSON(server.configPath, &restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.ActiveProfile != old.ID || restarted.ConnectedAt != 123 {
		t.Fatalf("restart state = %#v, want previous connection", restarted)
	}
}

func TestFailedRestorationAndStateClearRemainConflictAcrossRestart(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	old := profiles["wireguard/mullvad/mullvad_de"]
	target := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendWireGuard], old, 123)
	backends[BackendOpenVPN].startErrors[target.ID] = []error{errors.New("target failed")}
	backends[BackendWireGuard].startErrors[old.ID] = []error{errors.New("restore failed")}
	server.writeState = func(string, any) (stateWriteResult, error) {
		return stateWriteResult{}, errors.New("storage unavailable")
	}

	response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": target.ID})
	if response.Code != http.StatusInternalServerError || responseCode(t, response) != "state_clear_and_rollback_failed" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := server.snapshotConfig(); got.ActiveProfile != "" || got.ConnectedAt != 0 {
		t.Fatalf("in-memory state retained an unverified claim: %#v", got)
	}

	tokenPath := filepath.Join(t.TempDir(), "proxy-token")
	if err := os.WriteFile(tokenPath, []byte(testProxyToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(options{stateDir: filepath.Dir(server.configPath), trustedProxy: true, proxyTokenFile: tokenPath}, server.catalog, map[string]managedBackend{
		BackendOpenVPN: backends[BackendOpenVPN], BackendWireGuard: backends[BackendWireGuard],
	})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(restarted)
	if err != nil {
		t.Fatal(err)
	}
	status := request(t, router, http.MethodGet, "/api/status", nil)
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"lifecycle":"disconnected"`)) {
		t.Fatalf("restart status=%d body=%s", status.Code, status.Body.String())
	}
	if got := readConfigFile(t, restarted); got.ActiveProfile != "" || got.ConnectedAt != 0 {
		t.Fatalf("restart did not reconcile stale claim: %#v", got)
	}
}

func TestDisconnectStopFailureKeepsDurableAndPublicConflictState(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	active := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendOpenVPN], active, 123)
	backends[BackendOpenVPN].stopErrors[active.ID] = []error{errors.New("process group remains")}
	response := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if response.Code != http.StatusBadGateway || responseCode(t, response) != "disconnect_failed" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := readConfigFile(t, server); got.ActiveProfile != active.ID || got.ConnectedAt != 123 {
		t.Fatalf("failed stop changed durable state: %#v", got)
	}
	status := request(t, handler, http.MethodGet, "/api/status", nil)
	if status.Code != http.StatusConflict || !bytes.Contains(status.Body.Bytes(), []byte(`"lifecycle":"error_conflict"`)) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	cleanup := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if cleanup.Code != http.StatusOK {
		t.Fatalf("retry cleanup status=%d body=%s", cleanup.Code, cleanup.Body.String())
	}
}

func TestLifecycleIsObservableDuringDeterministicBarriers(t *testing.T) {
	t.Run("connecting", func(t *testing.T) {
		_, handler, backends, _ := testApp(t)
		backends[BackendOpenVPN].startEntered = make(chan struct{}, 1)
		backends[BackendOpenVPN].startRelease = make(chan struct{})
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			done <- request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		}()
		<-backends[BackendOpenVPN].startEntered
		status := request(t, handler, http.MethodGet, "/api/status", nil)
		if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"lifecycle":"connecting"`)) || !bytes.Contains(status.Body.Bytes(), []byte(`"id":"openvpn/generic/office"`)) {
			t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
		}
		close(backends[BackendOpenVPN].startRelease)
		if response := <-done; response.Code != http.StatusOK {
			t.Fatalf("connect status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("disconnecting", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		active := profiles["wireguard/mullvad/mullvad_de"]
		setConnected(t, server, backends[BackendWireGuard], active, 123)
		backends[BackendWireGuard].stopEntered = make(chan struct{}, 1)
		backends[BackendWireGuard].stopRelease = make(chan struct{})
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{}) }()
		<-backends[BackendWireGuard].stopEntered
		status := request(t, handler, http.MethodGet, "/api/status", nil)
		if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"lifecycle":"disconnecting"`)) || !bytes.Contains(status.Body.Bytes(), []byte(`"id":"`+active.ID+`"`)) {
			t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
		}
		close(backends[BackendWireGuard].stopRelease)
		if response := <-done; response.Code != http.StatusOK {
			t.Fatalf("disconnect status=%d body=%s", response.Code, response.Body.String())
		}
	})
}

func TestConflictAndUnavailableBackendResponses(t *testing.T) {
	t.Run("multiple active profiles", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		wg := profiles["wireguard/mullvad/mullvad_de"]
		ovpn := profiles["openvpn/generic/office"]
		setConnected(t, server, backends[BackendWireGuard], wg, 123)
		backends[BackendOpenVPN].active = &ovpn
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "wireguard/generic/home"})
		if response.Code != http.StatusConflict || responseCode(t, response) != "managed_state_conflict" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		status := request(t, handler, http.MethodGet, "/api/status", nil)
		if status.Code != http.StatusConflict || !bytes.Contains(status.Body.Bytes(), []byte(`"lifecycle":"error_conflict"`)) {
			t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
		}
		backends[BackendOpenVPN].active = nil
		response = request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "wireguard/generic/home"})
		if response.Code != http.StatusConflict {
			t.Fatalf("conflict latch admitted connect: status=%d body=%s", response.Code, response.Body.String())
		}
		cleanup := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
		if cleanup.Code != http.StatusOK {
			t.Fatalf("cleanup status=%d body=%s", cleanup.Code, cleanup.Body.String())
		}
		response = request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "wireguard/generic/home"})
		if response.Code != http.StatusOK {
			t.Fatalf("post-cleanup connect status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("multiple WireGuard profiles are explicitly cleaned", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		first := profiles["wireguard/mullvad/mullvad_de"]
		second := profiles["wireguard/generic/home"]
		setConnected(t, server, backends[BackendWireGuard], first, 123)
		backends[BackendWireGuard].additionalActive = []CatalogProfile{second}
		status := request(t, handler, http.MethodGet, "/api/status", nil)
		if status.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
		}
		cleanup := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
		if cleanup.Code != http.StatusOK || backends[BackendWireGuard].active != nil || len(backends[BackendWireGuard].additionalActive) != 0 {
			t.Fatalf("cleanup status=%d body=%s active=%v extra=%v", cleanup.Code, cleanup.Body.String(), backends[BackendWireGuard].active, backends[BackendWireGuard].additionalActive)
		}
	})

	t.Run("cross-backend conflict is explicitly cleaned", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		wg := profiles["wireguard/mullvad/mullvad_de"]
		ovpn := profiles["openvpn/generic/office"]
		setConnected(t, server, backends[BackendWireGuard], wg, 123)
		backends[BackendOpenVPN].active = &ovpn
		status := request(t, handler, http.MethodGet, "/api/status", nil)
		if status.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
		}
		cleanup := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
		if cleanup.Code != http.StatusOK || backends[BackendWireGuard].active != nil || backends[BackendOpenVPN].active != nil {
			t.Fatalf("cleanup status=%d body=%s wg=%v ovpn=%v", cleanup.Code, cleanup.Body.String(), backends[BackendWireGuard].active, backends[BackendOpenVPN].active)
		}
	})

	t.Run("observer availability failure aborts before mutation", func(t *testing.T) {
		server, handler, backends, profiles := testApp(t)
		active := profiles["wireguard/mullvad/mullvad_de"]
		setConnected(t, server, backends[BackendWireGuard], active, 123)
		backends[BackendWireGuard].availabilityErr = errors.New("wg observation failed")
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "backend_observation_failed" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if len(backends[BackendWireGuard].stops) != 0 || len(backends[BackendOpenVPN].starts) != 0 {
			t.Fatalf("mutation occurred: stops=%v starts=%v", backends[BackendWireGuard].stops, backends[BackendOpenVPN].starts)
		}
	})

	t.Run("target backend unavailable", func(t *testing.T) {
		_, handler, backends, _ := testApp(t)
		backends[BackendOpenVPN].availabilityErr = errors.New("binary absent")
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "backend_unavailable" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		profilesResponse := request(t, handler, http.MethodGet, "/api/profiles", nil)
		if profilesResponse.Code != http.StatusOK || !bytes.Contains(profilesResponse.Body.Bytes(), []byte(`"id":"openvpn/generic/office","backend":"openvpn"`)) || !bytes.Contains(profilesResponse.Body.Bytes(), []byte(`"available":false`)) {
			t.Fatalf("profiles status=%d body=%s", profilesResponse.Code, profilesResponse.Body.String())
		}
	})
}

func TestBuildBackendsMarksMissingProtocolTreeStaticallyDisabled(t *testing.T) {
	root := privateTestDir(t)
	for _, directory := range []string{filepath.Join(root, BackendWireGuard), filepath.Join(root, BackendWireGuard, "generic")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writePrivateTestFile(t, filepath.Join(root, BackendWireGuard, "generic", "home.conf"), "[Interface]\n")
	catalog, err := newProfileCatalog(root, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	backends := buildBackends(catalog)
	if backends[BackendOpenVPN].Enabled() {
		t.Fatal("missing OpenVPN profile tree was enabled")
	}
	if err := backends[BackendOpenVPN].Availability(context.Background()); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("OpenVPN availability error = %v", err)
	}
}

func TestRestartReconcilesDurableStateWithObservedNetwork(t *testing.T) {
	server, _, backends, profiles := testApp(t)
	active := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendOpenVPN], active, 123)
	backends[BackendOpenVPN].active = nil
	tokenPath := filepath.Join(t.TempDir(), "proxy-token")
	if err := os.WriteFile(tokenPath, []byte(testProxyToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(options{stateDir: filepath.Dir(server.configPath), trustedProxy: true, proxyTokenFile: tokenPath}, server.catalog, map[string]managedBackend{
		BackendOpenVPN: backends[BackendOpenVPN], BackendWireGuard: backends[BackendWireGuard],
	})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(restarted)
	if err != nil {
		t.Fatal(err)
	}
	status := request(t, router, http.MethodGet, "/api/status", nil)
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"connected":false`)) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	if got := readConfigFile(t, restarted); got.ActiveProfile != "" || got.ConnectedAt != 0 {
		t.Fatalf("stale durable state not reconciled: %#v", got)
	}
}

func TestDisconnectClearsStaleDurableConnectionWithoutStatusPoll(t *testing.T) {
	server, handler, backends, profiles := testApp(t)
	active := profiles["openvpn/generic/office"]
	setConnected(t, server, backends[BackendOpenVPN], active, 123)
	backends[BackendOpenVPN].active = nil

	response := request(t, handler, http.MethodPost, "/api/disconnect", map[string]string{})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	config := readConfigFile(t, server)
	if config.ActiveProfile != "" || config.ConnectedAt != 0 {
		t.Fatalf("stale durable state remains: %#v", config)
	}
}

func TestRestartDoesNotRetainAStaleClaimForDifferentObservedProfile(t *testing.T) {
	server, _, backends, profiles := testApp(t)
	persisted := profiles["openvpn/generic/office"]
	observed := profiles["wireguard/mullvad/mullvad_de"]
	setConnected(t, server, backends[BackendOpenVPN], persisted, 123)
	backends[BackendOpenVPN].active = nil
	backends[BackendWireGuard].active = &observed
	tokenPath := filepath.Join(t.TempDir(), "proxy-token")
	if err := os.WriteFile(tokenPath, []byte(testProxyToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(options{stateDir: filepath.Dir(server.configPath), trustedProxy: true, proxyTokenFile: tokenPath}, server.catalog, map[string]managedBackend{
		BackendOpenVPN: backends[BackendOpenVPN], BackendWireGuard: backends[BackendWireGuard],
	})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(restarted)
	if err != nil {
		t.Fatal(err)
	}
	status := request(t, router, http.MethodGet, "/api/status", nil)
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"id":"`+observed.ID+`"`)) || !bytes.Contains(status.Body.Bytes(), []byte(`"connected_since":0`)) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	if got := readConfigFile(t, restarted); got.ActiveProfile != "" || got.ConnectedAt != 0 {
		t.Fatalf("stale completed-transaction claim survived reconciliation: %#v", got)
	}
}

func TestMutationRequestValidation(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		mutate      func(*http.Request)
		wantStatus  int
		wantCode    string
	}{
		{name: "JSON with charset accepted", body: `{"profile":"openvpn/generic/office"}`, contentType: "application/json; charset=utf-8", wantStatus: http.StatusOK},
		{name: "missing media type", body: `{"profile":"openvpn/generic/office"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "vendor JSON rejected", body: `{"profile":"openvpn/generic/office"}`, contentType: "application/vnd.api+json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown field", body: `{"profile":"openvpn/generic/office","admin":true}`, contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "two values", body: `{"profile":"openvpn/generic/office"}{}`, contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate key", body: `{"profile":"wireguard/generic/home","profile":"openvpn/generic/office"}`, contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "null", body: `null`, contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "oversized trailing whitespace", body: `{"profile":"openvpn/generic/office"}` + string(bytes.Repeat([]byte(" "), maxRequestBody)), contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "cross-origin", body: `{"profile":"openvpn/generic/office"}`, contentType: "application/json", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, wantStatus: http.StatusForbidden, wantCode: "invalid_origin"},
		{name: "HTTP origin", body: `{"profile":"openvpn/generic/office"}`, contentType: "application/json", mutate: func(r *http.Request) { r.Header.Set("Origin", "http://vpn.example.test") }, wantStatus: http.StatusForbidden, wantCode: "invalid_origin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, handler, _, _ := testApp(t)
			response := rawRequest(handler, http.MethodPost, "/api/connect", tc.body, tc.contentType, tc.mutate)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, tc.wantStatus, response.Body.String())
			}
			if tc.wantCode != "" && responseCode(t, response) != tc.wantCode {
				t.Fatalf("code=%q, want %q; body=%s", responseCode(t, response), tc.wantCode, response.Body.String())
			}
		})
	}
}

func TestTrustedProxyAssertionsAreFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "token absent", mutate: func(r *http.Request) { r.Header.Del(proxyTokenHeader) }},
		{name: "token incorrect", mutate: func(r *http.Request) { r.Header.Set(proxyTokenHeader, "tunnelfolio-test-proxy-token-wrong") }},
		{name: "forwarded protocol absent", mutate: func(r *http.Request) { r.Header.Del("X-Forwarded-Proto") }},
		{name: "forwarded protocol HTTP", mutate: func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }},
		{name: "forwarded host absent", mutate: func(r *http.Request) { r.Header.Del("X-Forwarded-Host") }},
		{name: "authenticated user absent", mutate: func(r *http.Request) { r.Header.Del("X-Remote-User") }},
		{name: "authenticated user whitespace", mutate: func(r *http.Request) { r.Header.Set("X-Remote-User", "  ") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, handler, _, _ := testApp(t)
			response := rawRequest(handler, http.MethodPost, "/api/connect", `{"profile":"openvpn/generic/office"}`, "application/json", tc.mutate)
			if response.Code != http.StatusUnauthorized || responseCode(t, response) != "proxy_auth_required" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPreferencesArePreservedAcrossConnectionHistory(t *testing.T) {
	server, handler, _, _ := testApp(t)
	initial := Preferences{
		Favorites:    []string{"wireguard/generic/home", "openvpn/mullvad/mullvad_us"},
		Recents:      []string{"wireguard/generic/home", "openvpn/mullvad/mullvad_us"},
		TipDismissed: true,
	}
	response := request(t, handler, http.MethodPut, "/api/preferences", initial)
	if response.Code != http.StatusOK {
		t.Fatalf("save preferences status=%d body=%s", response.Code, response.Body.String())
	}
	for _, id := range []string{"openvpn/generic/office", "wireguard/mullvad/mullvad_de", "openvpn/generic/office"} {
		response = request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": id})
		if response.Code != http.StatusOK {
			t.Fatalf("connect %s status=%d body=%s", id, response.Code, response.Body.String())
		}
	}
	response = request(t, handler, http.MethodGet, "/api/preferences", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get preferences status=%d body=%s", response.Code, response.Body.String())
	}
	var got Preferences
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.TipDismissed || len(got.Favorites) != 2 || got.Favorites[0] != initial.Favorites[0] || got.Favorites[1] != initial.Favorites[1] {
		t.Fatalf("non-history preferences changed: %#v", got)
	}
	wantRecents := []string{"openvpn/generic/office", "wireguard/mullvad/mullvad_de", "wireguard/generic/home", "openvpn/mullvad/mullvad_us"}
	if len(got.Recents) != len(wantRecents) {
		t.Fatalf("recents=%v, want %v", got.Recents, wantRecents)
	}
	for index := range wantRecents {
		if got.Recents[index] != wantRecents[index] {
			t.Fatalf("recents=%v, want %v", got.Recents, wantRecents)
		}
	}
	var durable Preferences
	if err := readJSON(server.prefsPath, &durable); err != nil {
		t.Fatal(err)
	}
	if len(durable.Recents) != len(got.Recents) || durable.Recents[0] != got.Recents[0] {
		t.Fatalf("durable preferences=%#v, public preferences=%#v", durable, got)
	}
}

func TestPreferenceWriteFailurePreservesPreviousPublicAndDurableState(t *testing.T) {
	server, handler, _, _ := testApp(t)
	initial := Preferences{Favorites: []string{"wireguard/generic/home"}, Recents: []string{"openvpn/generic/office"}, TipDismissed: true}
	response := request(t, handler, http.MethodPut, "/api/preferences", initial)
	if response.Code != http.StatusOK {
		t.Fatalf("initial save status=%d body=%s", response.Code, response.Body.String())
	}
	server.writeState = func(path string, value any) (stateWriteResult, error) {
		if path == server.prefsPath {
			return stateWriteResult{}, errors.New("disk full")
		}
		return writeJSONAtomic(path, value)
	}
	replacement := Preferences{Favorites: []string{"openvpn/mullvad/mullvad_us"}}
	response = request(t, handler, http.MethodPut, "/api/preferences", replacement)
	if response.Code != http.StatusInternalServerError || responseCode(t, response) != "preferences_save_failed" {
		t.Fatalf("replacement status=%d body=%s", response.Code, response.Body.String())
	}
	response = request(t, handler, http.MethodGet, "/api/preferences", nil)
	var public Preferences
	if err := json.Unmarshal(response.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	var durable Preferences
	if err := readJSON(server.prefsPath, &durable); err != nil {
		t.Fatal(err)
	}
	if len(public.Favorites) != 1 || public.Favorites[0] != initial.Favorites[0] || !public.TipDismissed {
		t.Fatalf("public preferences changed after failed write: %#v", public)
	}
	if len(durable.Favorites) != 1 || durable.Favorites[0] != initial.Favorites[0] || !durable.TipDismissed {
		t.Fatalf("durable preferences changed after failed write: %#v", durable)
	}
}

func TestPublishedButUnsyncedPreferencesAreDeliberatelyRestored(t *testing.T) {
	t.Run("explicit save", func(t *testing.T) {
		server, handler, _, _ := testApp(t)
		previous := Preferences{Favorites: []string{"wireguard/generic/home"}, Recents: []string{"openvpn/generic/office"}, TipDismissed: true}
		if response := request(t, handler, http.MethodPut, "/api/preferences", previous); response.Code != http.StatusOK {
			t.Fatalf("initial save status=%d body=%s", response.Code, response.Body.String())
		}
		calls := 0
		server.writeState = func(path string, value any) (stateWriteResult, error) {
			result, err := writeJSONAtomic(path, value)
			if path == server.prefsPath {
				calls++
				if calls == 1 && err == nil {
					return stateWriteResult{Published: true}, errors.New("directory sync failed")
				}
			}
			return result, err
		}
		replacement := Preferences{Favorites: []string{"openvpn/mullvad/mullvad_us"}}
		response := request(t, handler, http.MethodPut, "/api/preferences", replacement)
		if response.Code != http.StatusInternalServerError || calls != 2 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
		}
		var disk Preferences
		if err := readJSON(server.prefsPath, &disk); err != nil {
			t.Fatal(err)
		}
		if !preferencesEqual(disk, previous) || !preferencesEqual(server.prefs, previous) {
			t.Fatalf("preferences diverged: disk=%#v memory=%#v", disk, server.prefs)
		}
	})

	t.Run("automatic recent", func(t *testing.T) {
		server, handler, _, _ := testApp(t)
		previous := server.prefs
		calls := 0
		server.writeState = func(path string, value any) (stateWriteResult, error) {
			result, err := writeJSONAtomic(path, value)
			if path == server.prefsPath {
				calls++
				if calls == 1 && err == nil {
					return stateWriteResult{Published: true}, errors.New("directory sync failed")
				}
			}
			return result, err
		}
		response := request(t, handler, http.MethodPost, "/api/connect", map[string]string{"profile": "openvpn/generic/office"})
		if response.Code != http.StatusOK || calls != 2 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
		}
		var disk Preferences
		if err := readJSON(server.prefsPath, &disk); err != nil {
			t.Fatal(err)
		}
		if !preferencesEqual(disk, previous) || !preferencesEqual(server.prefs, previous) {
			t.Fatalf("recent persistence diverged: disk=%#v memory=%#v", disk, server.prefs)
		}
	})
}

func preferencesEqual(left, right Preferences) bool {
	return slices.Equal(left.Favorites, right.Favorites) && slices.Equal(left.Recents, right.Recents) && left.TipDismissed == right.TipDismissed
}

func TestWriteJSONAtomicUsesPrivateMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if _, err := writeJSONAtomic(path, Config{Version: stateVersion}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%04o", info.Mode().Perm())
	}
}
