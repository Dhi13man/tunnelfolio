//go:build capacity

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/profiles"
)

const capacityBoundary = "TunnelfolioCapacityBoundary7MA4YWxkTrZu0gW"

func TestImportCapacityEnvelope(t *testing.T) {
	t.Run("50 and 100 profile capacity", func(t *testing.T) {
		fixture := newAPIFixture(t, false, true)
		importCapacityBatch(t, fixture.handler, capacityProfiles(0, 50, 0))
		assertAPIProfileCount(t, fixture.handler, 50)
		importCapacityBatch(t, fixture.handler, capacityProfiles(50, 50, 0))
		assertAPIProfileCount(t, fixture.handler, profiles.MaxProfiles)

		files := capacityProfiles(100, 1, 0)
		inspection := inspectCapacityBatch(t, fixture.handler, files)
		response := commitCapacityBatch(t, fixture.handler, files, inspection)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"library_capacity"`) {
			t.Fatalf("profile beyond remaining capacity = %d %s", response.Code, response.Body.String())
		}
		assertAPIProfileCount(t, fixture.handler, profiles.MaxProfiles)
	})

	t.Run("100 file batch", func(t *testing.T) {
		fixture := newAPIFixture(t, false, true)
		importCapacityBatch(t, fixture.handler, capacityProfiles(1000, profiles.MaxImportFiles, 0))
		assertAPIProfileCount(t, fixture.handler, profiles.MaxProfiles)
	})

	t.Run("concurrent HTTP request", func(t *testing.T) {
		fixture := newAPIFixture(t, false, true)
		body, contentType := capacityMultipart(t, capacityProfiles(0, 1, 0), nil)
		entered := make(chan struct{})
		release := make(chan struct{})
		blocked := &blockingCapacityReader{reader: bytes.NewReader(body), entered: entered, release: release}
		request := authenticatedRequest(http.MethodPost, "/api/imports/inspect", blocked, contentType)
		first := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			fixture.handler.ServeHTTP(first, request)
			close(done)
		}()
		<-entered

		second := performCapacityMultipart(t, fixture.handler, "/api/imports/inspect", capacityProfiles(1, 1, 0), nil)
		if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), `"code":"import_busy"`) {
			t.Fatalf("concurrent import = %d %s", second.Code, second.Body.String())
		}
		close(release)
		<-done
		if first.Code != http.StatusOK {
			t.Fatalf("first import = %d %s", first.Code, first.Body.String())
		}
	})

	t.Run("32 MiB at 512 KiB per second", func(t *testing.T) {
		fixture := newAPIFixture(t, false, true)
		files := fullCapacityProfiles(t, 32)
		body, contentType := capacityMultipart(t, files, nil)
		if len(body) != profiles.MaxImportRequest {
			t.Fatalf("multipart body = %d bytes, want %d", len(body), profiles.MaxImportRequest)
		}
		oversizedFiles := append([]profiles.ImportFile(nil), files...)
		oversizedFiles[len(oversizedFiles)-1].Bytes = append(append([]byte(nil), oversizedFiles[len(oversizedFiles)-1].Bytes...), '\n')
		oversized := performCapacityMultipart(t, fixture.handler, "/api/imports/inspect", oversizedFiles, nil)
		if oversized.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("aggregate request above 32 MiB = %d %s", oversized.Code, oversized.Body.String())
		}

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{
			Handler: fixture.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
			WriteTimeout: 130 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(listener) }()
		t.Cleanup(func() {
			_ = server.Shutdown(context.Background())
			if serveErr := <-serveDone; serveErr != nil && serveErr != http.ErrServerClosed {
				t.Errorf("capacity server: %v", serveErr)
			}
		})

		paced := &pacedCapacityReader{reader: bytes.NewReader(body), bytesPerSecond: 512 << 10}
		request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/api/imports/inspect", paced)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "gateway.example.test"
		request.Header.Set("Content-Type", contentType)
		request.Header.Set(ProxyTokenHeader, testProxyToken)
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("X-Forwarded-Host", "gateway.example.test")
		request.Header.Set("X-Remote-User", "operator@example.test")

		started := time.Now()
		response, err := (&http.Client{Timeout: 110 * time.Second}).Do(request)
		elapsed := time.Since(started)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("slow maximum request = %d %s", response.StatusCode, responseBody)
		}
		var inspection profiles.Inspection
		if err := json.Unmarshal(responseBody, &inspection); err != nil {
			t.Fatal(err)
		}
		if !inspection.CommitReady || len(inspection.InspectionRecords) != len(files) {
			t.Fatalf("slow maximum inspection = %+v", inspection)
		}
		if elapsed < 60*time.Second || elapsed >= 110*time.Second {
			t.Fatalf("slow maximum request elapsed %s outside the expected envelope", elapsed)
		}
		t.Logf("capacity receipt candidate=%s body_bytes=%d files=%d rate_bytes_per_second=%d elapsed=%s", os.Getenv("CANDIDATE_COMMIT"), len(body), len(files), 512<<10, elapsed.Round(time.Millisecond))
	})
}

type blockingCapacityReader struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingCapacityReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() {
		close(r.entered)
		<-r.release
	})
	return r.reader.Read(buffer)
}

type pacedCapacityReader struct {
	reader         io.Reader
	bytesPerSecond int64
	started        time.Time
	read           int64
}

func (r *pacedCapacityReader) Read(buffer []byte) (int, error) {
	if len(buffer) > 32<<10 {
		buffer = buffer[:32<<10]
	}
	if r.started.IsZero() {
		r.started = time.Now()
	}
	count, err := r.reader.Read(buffer)
	r.read += int64(count)
	deadline := r.started.Add(time.Duration(r.read) * time.Second / time.Duration(r.bytesPerSecond))
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
	return count, err
}

func importCapacityBatch(t *testing.T, handler http.Handler, files []profiles.ImportFile) {
	t.Helper()
	inspection := inspectCapacityBatch(t, handler, files)
	response := commitCapacityBatch(t, handler, files, inspection)
	if response.Code != http.StatusOK {
		t.Fatalf("commit %d files = %d %s", len(files), response.Code, response.Body.String())
	}
}

func inspectCapacityBatch(t *testing.T, handler http.Handler, files []profiles.ImportFile) profiles.Inspection {
	t.Helper()
	response := performCapacityMultipart(t, handler, "/api/imports/inspect", files, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("inspect %d files = %d %s", len(files), response.Code, response.Body.String())
	}
	var inspection profiles.Inspection
	if err := json.Unmarshal(response.Body.Bytes(), &inspection); err != nil {
		t.Fatal(err)
	}
	if !inspection.CommitReady || len(inspection.InspectionRecords) != len(files) {
		t.Fatalf("inspection = %+v", inspection)
	}
	return inspection
}

func commitCapacityBatch(t *testing.T, handler http.Handler, files []profiles.ImportFile, inspection profiles.Inspection) *httptest.ResponseRecorder {
	t.Helper()
	metadata := make(map[int]map[string]string, len(files))
	for ordinal := range files {
		metadata[ordinal] = map[string]string{"display_name": fmt.Sprintf("Profile %03d", ordinal+1), "group": "Capacity"}
	}
	fields := map[string][]byte{
		"inspection_records":   mustJSON(t, inspection.InspectionRecords),
		"metadata":             mustJSON(t, metadata),
		"receipt":              []byte(inspection.Receipt),
		"trust_profile_policy": []byte("true"),
		"library_revision":     []byte(strconv.FormatUint(inspection.LibraryRevision, 10)),
	}
	return performCapacityMultipart(t, handler, "/api/profiles/import", files, fields)
}

func assertAPIProfileCount(t *testing.T, handler http.Handler, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/profiles", nil, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("list profiles = %d %s", response.Code, response.Body.String())
	}
	var listed []json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != want {
		t.Fatalf("listed profiles = %d, want %d", len(listed), want)
	}
}

func performCapacityMultipart(t *testing.T, handler http.Handler, requestPath string, files []profiles.ImportFile, fields map[string][]byte) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := capacityMultipart(t, files, fields)
	request := authenticatedRequest(http.MethodPost, requestPath, bytes.NewReader(body), contentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func capacityMultipart(t *testing.T, files []profiles.ImportFile, fields map[string][]byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(capacityBoundary); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		part, err := writer.CreateFormFile("files", file.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file.Bytes); err != nil {
			t.Fatal(err)
		}
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
	return body.Bytes(), writer.FormDataContentType()
}

func capacityProfiles(start, count, size int) []profiles.ImportFile {
	files := make([]profiles.ImportFile, count)
	for offset := range files {
		ordinal := start + offset
		base := []byte(fmt.Sprintf("client\ndev tun\nproto udp\nremote vpn-%03d.example.test 1194\nnobind\n", ordinal))
		if size > len(base) {
			base = append(base, capacityPadding(size-len(base))...)
		}
		files[offset] = profiles.ImportFile{Name: fmt.Sprintf("profile-%03d.ovpn", ordinal), Bytes: base}
	}
	return files
}

func fullCapacityProfiles(t *testing.T, count int) []profiles.ImportFile {
	t.Helper()
	files := capacityProfiles(2000, count, 0)
	baseBody, _ := capacityMultipart(t, files, nil)
	payloadBytes := 0
	for _, file := range files {
		payloadBytes += len(file.Bytes)
	}
	overhead := len(baseBody) - payloadBytes
	targetPayload := profiles.MaxImportRequest - overhead
	if targetPayload <= 0 || targetPayload > count*profiles.MaxProfileBytes {
		t.Fatalf("cannot construct maximum multipart payload: overhead=%d target=%d", overhead, targetPayload)
	}
	baseSize := targetPayload / count
	remainder := targetPayload % count
	for index := range files {
		size := baseSize
		if index < remainder {
			size++
		}
		if size > profiles.MaxProfileBytes {
			t.Fatalf("profile %d size %d exceeds per-file limit", index, size)
		}
		files[index] = capacityProfiles(2000+index, 1, size)[0]
	}
	return files
}

func capacityPadding(size int) []byte {
	padding := make([]byte, 0, size)
	for size > 0 {
		if size == 1 {
			padding = append(padding, '\n')
			break
		}
		line := min(size, 1024)
		padding = append(padding, '#')
		padding = append(padding, bytes.Repeat([]byte{'x'}, line-2)...)
		padding = append(padding, '\n')
		size -= line
	}
	return padding
}
