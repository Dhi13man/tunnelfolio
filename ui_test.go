package main

import (
	"regexp"
	"strings"
	"testing"
)

func readEmbeddedUIFile(t *testing.T, name string) string {
	t.Helper()
	data, err := templates.ReadFile("templates/" + name)
	if err != nil {
		t.Fatalf("read embedded UI file %q: %v", name, err)
	}
	return string(data)
}

func TestUIUsesExternalEmbeddedAssetsWithoutInlineExecution(t *testing.T) {
	html := readEmbeddedUIFile(t, "index.html")

	for _, required := range []string{
		`<link rel="stylesheet" href="/assets/app.css">`,
		`<script src="/assets/app.js" defer></script>`,
	} {
		if !strings.Contains(html, required) {
			t.Errorf("index.html missing %q", required)
		}
	}
	for name, pattern := range map[string]string{
		"inline script":          `<script(?:\s[^>]*)?>\s*[^<\s]`,
		"inline style block":     `<style(?:\s[^>]*)?>`,
		"inline event handler":   `(?i)\son[a-z]+\s*=`,
		"inline style attribute": `(?i)\sstyle\s*=`,
		"external dependency":    `(?i)(?:src|href)\s*=\s*["']https?://`,
	} {
		if regexp.MustCompile(pattern).MatchString(html) {
			t.Errorf("index.html contains forbidden %s", name)
		}
	}
}

func TestUIConstructsUntrustedContentWithSafeDOMAPIs(t *testing.T) {
	javascript := readEmbeddedUIFile(t, "app.js")

	for name, pattern := range map[string]string{
		"innerHTML":            `\.innerHTML\b`,
		"outerHTML":            `\.outerHTML\b`,
		"HTML insertion":       `\binsertAdjacentHTML\b`,
		"document.write":       `\bdocument\.write\b`,
		"string evaluation":    `\beval\s*\(`,
		"Function constructor": `\bnew\s+Function\b`,
		"event attribute":      `setAttribute\s*\(\s*["']on`,
	} {
		if regexp.MustCompile(pattern).MatchString(javascript) {
			t.Errorf("app.js contains forbidden %s sink", name)
		}
	}
	for _, required := range []string{"document.createElement", ".textContent", ".replaceChildren"} {
		if !strings.Contains(javascript, required) {
			t.Errorf("app.js does not use required safe DOM primitive %q", required)
		}
	}
}

func TestUIExposesSemanticAndPersistentAccessibleStates(t *testing.T) {
	html := readEmbeddedUIFile(t, "index.html")
	javascript := readEmbeddedUIFile(t, "app.js")
	css := readEmbeddedUIFile(t, "app.css")

	for _, required := range []string{
		`<html lang="en">`,
		`href="#main-content"`,
		`<main class="shell" id="main-content" tabindex="-1">`,
		`<h1 id="connection-title" tabindex="-1">`,
		`role="search"`,
		`<dialog class="settings-dialog" id="settings-dialog" aria-labelledby="settings-title">`,
		`id="error-panel" aria-labelledby="error-title" hidden`,
		`id="status-announcer" role="status" aria-live="polite" aria-atomic="true"`,
	} {
		if !strings.Contains(html, required) {
			t.Errorf("index.html missing accessible contract %q", required)
		}
	}
	for _, required := range []string{
		"elements.dialog.showModal()",
		"elements.dialogTitle.focus()",
		`elements.dialog.addEventListener("close", () => elements.settingsOpen.focus())`,
		"elements.errorPanel.hidden = false",
		"window.confirm(",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("app.js missing interaction contract %q", required)
		}
	}
	for _, required := range []string{":focus-visible", "prefers-reduced-motion:reduce", "forced-colors:active"} {
		if !strings.Contains(css, required) {
			t.Errorf("app.css missing preference/focus contract %q", required)
		}
	}
}

func TestUIModelsProfilesByBackendProviderAndOpaqueID(t *testing.T) {
	javascript := readEmbeddedUIFile(t, "app.js")

	for _, required := range []string{
		"profile.id || profile.profile_id || profile.file",
		"profile.backend || profile.protocol",
		`profile.provider || "generic"`,
		`api("POST", "/api/connect", { profile: profile.id })`,
		`api("PUT", "/api/preferences", {`,
		"profile.country",
		"profile.flag",
		"profile.region",
		"payload.lifecycle || payload.state || payload.status",
		"payload.capabilities",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("app.js missing backend-neutral contract %q", required)
		}
	}
	for _, assumption := range []string{"mullvad_", "wg-quick", "wireguard_unavailable"} {
		if strings.Contains(strings.ToLower(javascript), assumption) {
			t.Errorf("app.js contains backend/provider-specific assumption %q", assumption)
		}
	}
}
