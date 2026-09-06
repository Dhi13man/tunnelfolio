package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmbeddedApplicationBoundary(t *testing.T) {
	index, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	for _, required := range []string{
		`<link rel="stylesheet" href="/assets/app.css">`,
		`<script type="module" src="/assets/app.js"></script>`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("index is missing %q", required)
		}
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "javascript:") || strings.Contains(html, " onerror=") || strings.Contains(html, " onclick=") {
		t.Fatal("index contains inline executable content")
	}

	assets := map[string]string{
		"app.css":            "text/css; charset=utf-8",
		"api.js":             "text/javascript; charset=utf-8",
		"app.js":             "text/javascript; charset=utf-8",
		"connection.js":      "text/javascript; charset=utf-8",
		"detail.js":          "text/javascript; charset=utf-8",
		"import.js":          "text/javascript; charset=utf-8",
		"library.js":         "text/javascript; charset=utf-8",
		"state.js":           "text/javascript; charset=utf-8",
		"manrope-latin.woff2": "font/woff2",
		"Manrope-OFL.txt":     "text/plain; charset=utf-8",
		"Lucide-LICENSE.txt":  "text/plain; charset=utf-8",
	}
	for name, expectedType := range assets {
		data, contentType, assetErr := Asset(name)
		if assetErr != nil {
			t.Fatalf("Asset(%q): %v", name, assetErr)
		}
		if len(bytes.TrimSpace(data)) == 0 || contentType != expectedType {
			t.Fatalf("Asset(%q) returned %d bytes as %q", name, len(data), contentType)
		}
		if name == "manrope-latin.woff2" && !bytes.HasPrefix(data, []byte("wOF2")) {
			t.Fatal("font asset is not a WOFF2 file")
		}
		if strings.HasSuffix(name, ".js") {
			source := string(data)
			for _, sink := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
				if strings.Contains(source, sink) {
					t.Fatalf("Asset(%q) contains unsafe DOM sink %q", name, sink)
				}
			}
		}
	}
	for _, name := range []string{"", "../index.html", "nested/app.js", "old-app.js", "../assets/manrope-latin.woff2", "other.woff2", "other.txt", "manrope-latin.woff2/extra"} {
		if _, _, err := Asset(name); err == nil {
			t.Fatalf("Asset(%q) unexpectedly succeeded", name)
		}
	}
}
