package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/manager"
	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
)

const testProxyToken = "test-proxy-token-value-with-32-bytes-minimum"

type apiFakeBackend struct {
	protocol string
	mu       sync.Mutex
	active   map[string]bool
}

func (b *apiFakeBackend) Protocol() string                { return b.protocol }
func (b *apiFakeBackend) Available(context.Context) error { return nil }
func (b *apiFakeBackend) Shutdown(context.Context) error  { return nil }
func (b *apiFakeBackend) Status(context.Context, tunnel.Profile) (tunnel.ProtocolStatus, error) {
	return tunnel.ProtocolStatus{State: "active"}, nil
}
func (b *apiFakeBackend) Observe(_ context.Context, candidates []tunnel.Profile) ([]tunnel.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result []tunnel.Observation
	for _, profile := range candidates {
		if b.active[profile.ID] {
			result = append(result, tunnel.Observation{ProfileID: profile.ID, Protocol: profile.Protocol, Identifier: profile.Identifier})
		}
	}
	return result, nil
}
func (b *apiFakeBackend) Start(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	b.active[profile.ID] = true
	b.mu.Unlock()
	return nil
}
func (b *apiFakeBackend) Stop(_ context.Context, profile tunnel.Profile) error {
	b.mu.Lock()
	delete(b.active, profile.ID)
	b.mu.Unlock()
	return nil
}

type apiFixture struct {
	handler  http.Handler
	store    *profiles.Store
	manager  *manager.Manager
	logs     *bytes.Buffer
	runtime  string
	backends map[string]*apiFakeBackend
}

func newAPIFixture(t *testing.T, readOnly, trusted bool) apiFixture {
	t.Helper()
	stateRoot := privateTempDir(t)
	store, err := profiles.OpenStore(profiles.StoreOptions{Root: stateRoot, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	backends := map[string]*apiFakeBackend{
		profiles.ProtocolOpenVPN:   {protocol: profiles.ProtocolOpenVPN, active: make(map[string]bool)},
		profiles.ProtocolWireGuard: {protocol: profiles.ProtocolWireGuard, active: make(map[string]bool)},
	}
	managed, err := manager.New(manager.Options{
		Store: store, ReadOnly: readOnly, Backends: map[string]tunnel.Backend{
			profiles.ProtocolOpenVPN: backends[profiles.ProtocolOpenVPN], profiles.ProtocolWireGuard: backends[profiles.ProtocolWireGuard],
		}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var importer *profiles.ImportService
	if !readOnly {
		importer, err = profiles.NewImportService(profiles.ImportServiceOptions{
			Store: store, Random: rand.Reader, WireGuardChecker: profiles.CompatibilityCheckFunc(func([]byte) error { return nil }),
			CommitAdmission: managed.AcquireLibraryOperation,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	logs := new(bytes.Buffer)
	runtimeDir := privateTempDir(t)
	handler, err := New(Options{
		Manager: managed, Imports: importer, RuntimeDir: runtimeDir, TrustedProxy: trusted,
		ProxyToken: []byte(testProxyToken), ReadOnly: readOnly, Logger: log.New(logs, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return apiFixture{handler: handler, store: store, manager: managed, logs: logs, runtime: runtimeDir, backends: backends}
}

func TestTrustedProxyAndOriginBoundaries(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	unauthorized := httptest.NewRecorder()
	fixture.handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("direct backend status = %d", unauthorized.Code)
	}

	badOrigin := authenticatedRequest(http.MethodPost, "/api/disconnect", nil, "application/json")
	badOrigin.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, badOrigin)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "invalid_origin") {
		t.Fatalf("bad-origin response = %d %s", response.Code, response.Body.String())
	}

	customPort := authenticatedRequest(http.MethodPost, "/api/disconnect", nil, "application/json")
	customPort.Header.Set("Origin", "https://gateway.example.test:8443")
	customPort.Header.Set("X-Forwarded-Host", "gateway.example.test:8443")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, customPort)
	if response.Code != http.StatusOK {
		t.Fatalf("matching custom-port origin response = %d %s", response.Code, response.Body.String())
	}

	readOnly := newAPIFixture(t, true, false)
	request := httptest.NewRequest(http.MethodPost, "/api/disconnect", nil)
	response = httptest.NewRecorder()
	readOnly.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "read_only") {
		t.Fatalf("read-only mutation = %d %s", response.Code, response.Body.String())
	}
}

func TestPreferencesEncodeEmptyCollectionsAsArrays(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	requests := []*http.Request{
		authenticatedRequest(http.MethodGet, "/api/preferences", nil, ""),
		authenticatedRequest(http.MethodPut, "/api/preferences", strings.NewReader(`{"favorites":[],"recents":[],"startup_mode":"manual"}`), "application/json"),
	}
	for _, request := range requests {
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, `"favorites":[]`) || !strings.Contains(body, `"recents":[]`) {
			t.Fatalf("%s preferences = %d %s", request.Method, response.Code, body)
		}
	}
}

func TestStrictJSONRejectsUnknownDuplicateAndTrailingValues(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	tests := []string{
		`{"profile":"one","extra":true}`,
		`{"profile":"one","profile":"two"}`,
		`{"profile":"one"}{"profile":"two"}`,
	}
	for _, body := range tests {
		request := authenticatedRequest(http.MethodPost, "/api/connect", strings.NewReader(body), "application/json")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q returned %d: %s", body, response.Code, response.Body.String())
		}
	}
}

func TestJSONEnvelopeStatusCodes(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	for name, test := range map[string]struct {
		contentType string
		body        string
		want        int
	}{
		"unsupported media": {"text/plain", `{}`, http.StatusUnsupportedMediaType},
		"oversized body":    {"application/json", strings.Repeat(" ", maxJSONBody+1), http.StatusRequestEntityTooLarge},
		"malformed JSON":    {"application/json", `{`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request := authenticatedRequest(http.MethodPost, "/api/connect", strings.NewReader(test.body), test.contentType)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("response = %d %s, want %d", response.Code, response.Body.String(), test.want)
			}
		})
	}
}

func TestImportInspectCommitReplayAndSafeResponses(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	profileBytes := validAPIOpenVPN()
	inspection := inspectProfile(t, fixture.handler, "office.ovpn", profileBytes, nil)
	if !inspection.CommitReady || inspection.Receipt == "" || len(inspection.InspectionRecords) != 1 {
		t.Fatalf("inspection = %+v", inspection)
	}
	metadata := []byte(`{"0":{"display_name":"Office","group":"Work","location":"London"}}`)
	fields := map[string][]byte{
		"inspection_records": mustJSON(t, inspection.InspectionRecords), "metadata": metadata,
		"receipt": []byte(inspection.Receipt), "trust_profile_policy": []byte("true"),
		"library_revision": []byte(strconv.FormatUint(inspection.LibraryRevision, 10)),
	}
	response := performMultipart(t, fixture.handler, "/api/profiles/import", "office.ovpn", profileBytes, fields)
	if response.Code != http.StatusOK {
		t.Fatalf("commit = %d %s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"content_sha256", "wireguard_public_key_sha256", string(profileBytes)} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("commit response exposed %q: %s", forbidden, response.Body.String())
		}
	}
	if len(fixture.store.List()) != 1 {
		t.Fatalf("profiles after commit = %d", len(fixture.store.List()))
	}
	replay := performMultipart(t, fixture.handler, "/api/profiles/import", "office.ovpn", profileBytes, fields)
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) {
		t.Fatalf("replay = %d %s", replay.Code, replay.Body.String())
	}
	entries, err := os.ReadDir(fixture.runtime)
	if err != nil || len(entries) != 0 {
		t.Fatalf("request staging survived: entries=%d err=%v", len(entries), err)
	}
}

func TestImportMetadataErrorNamesOnlyFileFieldAndCode(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	profileBytes := validAPIOpenVPN()
	inspection := inspectProfile(t, fixture.handler, "office.ovpn", profileBytes, nil)
	canary := strings.Repeat("界", 86)
	fields := map[string][]byte{
		"inspection_records": mustJSON(t, inspection.InspectionRecords),
		"metadata":           []byte(`{"0":{"display_name":"Office","group":"` + canary + `","location":""}}`),
		"receipt":            []byte(inspection.Receipt), "trust_profile_policy": []byte("true"),
		"library_revision": []byte(strconv.FormatUint(inspection.LibraryRevision, 10)),
	}
	response := performMultipart(t, fixture.handler, "/api/profiles/import", "office.ovpn", profileBytes, fields)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), `"file":0`) ||
		!strings.Contains(response.Body.String(), `"field":"group"`) || !strings.Contains(response.Body.String(), `"code":"length_limit"`) {
		t.Fatalf("metadata error = %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), canary) {
		t.Fatal("metadata response exposed the rejected value")
	}
}

func TestImportRejectsExecutableProfileWithoutEchoingCanary(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	canary := "secret-upload-canary"
	data := append(validAPIOpenVPN(), []byte("up /tmp/"+canary+"\n")...)
	response := performMultipart(t, fixture.handler, "/api/imports/inspect", "unsafe.ovpn", data, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "unsafe_directive") {
		t.Fatalf("unsafe inspection = %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), canary) || strings.Contains(fixture.logs.String(), canary) {
		t.Fatal("uploaded canary escaped into response or logs")
	}
	if strings.Contains(response.Body.String(), "receipt") || strings.Contains(response.Body.String(), "expires_at") {
		t.Fatalf("non-ready inspection exposed a receipt envelope: %s", response.Body.String())
	}
}

func TestMultipartRejectsTraversalUnknownPartsAndOversizeFile(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	traversal := performMultipart(t, fixture.handler, "/api/imports/inspect", "../escape.ovpn", validAPIOpenVPN(), nil)
	if traversal.Code != http.StatusBadRequest {
		t.Fatalf("traversal = %d %s", traversal.Code, traversal.Body.String())
	}
	unknown := performMultipart(t, fixture.handler, "/api/imports/inspect", "office.ovpn", validAPIOpenVPN(), map[string][]byte{"unknown": []byte("x")})
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown part = %d %s", unknown.Code, unknown.Body.String())
	}
	oversize := performMultipart(t, fixture.handler, "/api/imports/inspect", "large.ovpn", bytes.Repeat([]byte{'x'}, profiles.MaxProfileBytes+1), nil)
	if oversize.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d %s", oversize.Code, oversize.Body.String())
	}
	unsupported := httptest.NewRecorder()
	fixture.handler.ServeHTTP(unsupported, authenticatedRequest(http.MethodPost, "/api/imports/inspect", strings.NewReader("not multipart"), "application/octet-stream"))
	if unsupported.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported multipart media = %d %s", unsupported.Code, unsupported.Body.String())
	}
	malformed := httptest.NewRecorder()
	fixture.handler.ServeHTTP(malformed, authenticatedRequest(http.MethodPost, "/api/imports/inspect", strings.NewReader("unterminated"), "multipart/form-data; boundary=unfinished"))
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed multipart = %d %s", malformed.Code, malformed.Body.String())
	}
}

func TestMetadataPatchNullSemanticsAndRemovalGuard(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	inspection := inspectProfile(t, fixture.handler, "office.ovpn", validAPIOpenVPN(), nil)
	fields := map[string][]byte{
		"inspection_records": mustJSON(t, inspection.InspectionRecords),
		"metadata":           []byte(`{"0":{"display_name":"Office","group":"Work","location":"London"}}`),
		"receipt":            []byte(inspection.Receipt), "trust_profile_policy": []byte("true"),
		"library_revision": []byte(strconv.FormatUint(inspection.LibraryRevision, 10)),
	}
	commit := performMultipart(t, fixture.handler, "/api/profiles/import", "office.ovpn", validAPIOpenVPN(), fields)
	if commit.Code != http.StatusOK {
		t.Fatalf("commit = %d %s", commit.Code, commit.Body.String())
	}
	id := fixture.store.List()[0].ID
	patch := authenticatedRequest(http.MethodPatch, "/api/profiles/"+id, strings.NewReader(`{"location":null}`), "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, patch)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"location"`) {
		t.Fatalf("clear location = %d %s", response.Code, response.Body.String())
	}
	nullName := authenticatedRequest(http.MethodPatch, "/api/profiles/"+id, strings.NewReader(`{"display_name":null}`), "application/json")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, nullName)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("null display name = %d %s", response.Code, response.Body.String())
	}
	if err := fixture.manager.Connect(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	detail := httptest.NewRecorder()
	fixture.handler.ServeHTTP(detail, authenticatedRequest(http.MethodGet, "/api/profiles/"+id, nil, ""))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"current":true`) || !strings.Contains(detail.Body.String(), `"protocol_status"`) {
		t.Fatalf("profile detail = %d %s", detail.Code, detail.Body.String())
	}
	remove := authenticatedRequest(http.MethodDelete, "/api/profiles/"+id, nil, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, remove)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "profile_active") {
		t.Fatalf("active removal = %d %s", response.Code, response.Body.String())
	}
}

func TestRequestLoggerEscapesDecodedControlCharacters(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	request := authenticatedRequest(http.MethodGet, "/missing%0aforged-entry", nil, "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	logs := fixture.logs.String()
	if strings.Contains(logs, "\nforged-entry") || !strings.Contains(logs, `%0aforged-entry`) {
		t.Fatalf("unsafe request log = %q", logs)
	}
}

func TestStaticSurfaceUsesSecurityHeadersAndNoSecretSinks(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	for _, path := range []string{"/", "/assets/app.js", "/assets/app.css"} {
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, path, nil, ""))
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, response.Code)
		}
		if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s missing security headers", path)
		}
		if strings.Contains(response.Body.String(), "innerHTML") || strings.Contains(response.Body.String(), "document.write") {
			t.Fatalf("%s contains an unsafe DOM sink", path)
		}
	}
}

func inspectProfile(t *testing.T, handler http.Handler, filename string, data []byte, fields map[string][]byte) profiles.Inspection {
	t.Helper()
	response := performMultipart(t, handler, "/api/imports/inspect", filename, data, fields)
	if response.Code != http.StatusOK {
		t.Fatalf("inspect = %d %s", response.Code, response.Body.String())
	}
	var inspection profiles.Inspection
	if err := json.Unmarshal(response.Body.Bytes(), &inspection); err != nil {
		t.Fatal(err)
	}
	return inspection
}

func performMultipart(t *testing.T, handler http.Handler, path, filename string, data []byte, fields map[string][]byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	for name, value := range fields {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(http.MethodPost, path, &body, writer.FormDataContentType())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authenticatedRequest(method, path string, body io.Reader, contentType string) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.Host = "gateway.example.test"
	request.Header.Set(ProxyTokenHeader, testProxyToken)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "gateway.example.test")
	request.Header.Set("X-Remote-User", "operator@example.test")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return request
}

func validAPIOpenVPN() []byte {
	return []byte("client\ndev tun\nproto udp\nremote vpn.example.test 1194\nnobind\n")
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProtocolOverrideIsReceiptBound(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	data := validAPIOpenVPN()
	inspection := inspectProfile(t, fixture.handler, "profile.conf", data, map[string][]byte{"protocol_overrides": []byte(`{"0":"openvpn"}`)})
	fields := map[string][]byte{
		"inspection_records": mustJSON(t, inspection.InspectionRecords),
		"metadata":           []byte(`{"0":{"display_name":"Office","group":"Work","location":""}}`),
		"receipt":            []byte(inspection.Receipt), "trust_profile_policy": []byte("true"),
		"library_revision": []byte(strconv.FormatUint(inspection.LibraryRevision, 10)),
	}
	response := performMultipart(t, fixture.handler, "/api/profiles/import", "profile.conf", data, fields)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_receipt") {
		t.Fatalf("changed override = %d %s", response.Code, response.Body.String())
	}
}

func TestErrorResponsesNeverExposeInternalErrors(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	fixture.backends[profiles.ProtocolOpenVPN].mu.Lock()
	fixture.backends[profiles.ProtocolOpenVPN].active["missing-secret-id"] = true
	fixture.backends[profiles.ProtocolOpenVPN].mu.Unlock()
	request := authenticatedRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"profile":"does-not-exist"}`), "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "missing-secret-id") {
		t.Fatalf("error response = %d %s", response.Code, response.Body.String())
	}
}

func TestNoBodyDeleteRejectsChunkedContent(t *testing.T) {
	fixture := newAPIFixture(t, false, true)
	request := authenticatedRequest(http.MethodDelete, "/api/profiles/id", strings.NewReader("x"), "text/plain")
	request.ContentLength = -1
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatalf("chunked delete body was accepted: %s", response.Body.String())
	}
}
