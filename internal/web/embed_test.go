package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmbeddedApplicationBoundary(t *testing.T) {
	assets := map[string]string{
		"app.css":                "text/css; charset=utf-8",
		"api.js":                 "text/javascript; charset=utf-8",
		"app.js":                 "text/javascript; charset=utf-8",
		"connection.js":          "text/javascript; charset=utf-8",
		"detail.js":              "text/javascript; charset=utf-8",
		"import.js":              "text/javascript; charset=utf-8",
		"library.js":             "text/javascript; charset=utf-8",
		"profile-symbol.js":      "text/javascript; charset=utf-8",
		"state.js":               "text/javascript; charset=utf-8",
		"manrope-latin.woff2":    "font/woff2",
		"noto-color-emoji.woff2": "font/woff2",
		"Manrope-OFL.txt":        "text/plain; charset=utf-8",
		"NotoColorEmoji-OFL.txt": "text/plain; charset=utf-8",
		"Lucide-LICENSE.txt":     "text/plain; charset=utf-8",
	}
	for name, expectedType := range assets {
		data, contentType, assetErr := Asset(name)
		if assetErr != nil {
			t.Fatalf("Asset(%q): %v", name, assetErr)
		}
		if contentType != expectedType {
			t.Fatalf("Asset(%q) returned %q, want %q", name, contentType, expectedType)
		}
		if strings.HasSuffix(name, ".woff2") && !bytes.HasPrefix(data, []byte("wOF2")) {
			t.Fatal("font asset is not a WOFF2 file")
		}
	}
	for _, name := range []string{"", "../index.html", "nested/app.js", "old-app.js", "../assets/manrope-latin.woff2", "other.woff2", "other.txt", "manrope-latin.woff2/extra"} {
		if _, _, err := Asset(name); err == nil {
			t.Fatalf("Asset(%q) unexpectedly succeeded", name)
		}
	}
}
