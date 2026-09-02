package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVPNConfigInspectorAcceptsQuotedEscapedCommentedAndContinuedPaths(t *testing.T) {
	provider := privateTestDir(t)
	secretNames := []string{"auth file", "ca.crt", "client.crt", "client.key", "bundle.p12", "ta.key", "crypt.key", "crypt-v2.key", "crl.pem"}
	for _, name := range secretNames {
		writePrivateTestFile(t, filepath.Join(provider, name), "fixture")
	}
	profile := filepath.Join(provider, "client.ovpn")
	writePrivateTestFile(t, profile, strings.Join([]string{
		"client # ordinary comment",
		`auth-user-pass "auth file" ; inline comment`,
		`ca ca.crt`,
		`cert client.crt`,
		`key client.key`,
		`pkcs12 bundle.p12`,
		`tls-auth ta.key`,
		`tls-crypt crypt.key`,
		`tls-crypt-v2 crypt-v2.key`,
		"crl-verify crl\\",
		".pem",
		`setenv harmless "escaped\ value"`,
		"",
	}, "\n"))

	if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestOpenVPNConfigInspectorRejectsOwnershipConflictsAndMalformedLines(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"include", "config other.ovpn"},
		{"long option include", "--config other.ovpn"},
		{"daemon", "daemon"},
		{"management", "management 127.0.0.1 1234"},
		{"management client", "management-client"},
		{"write pid", "writepid process.pid"},
		{"working directory", "cd /tmp"},
		{"chroot", "chroot /tmp"},
		{"interactive auth", "auth-user-pass stdin"},
		{"missing secret argument", "ca"},
		{"extra secret argument", "key first second"},
		{"unsupported secret", "secret static.key"},
		{"unsupported proxy auth", "http-proxy-user-pass proxy.auth"},
		{"unsupported socks auth", "socks-proxy localhost 1080 proxy.auth"},
		{"empty directive", `"" value`},
		{"control character", "remote host\x00name"},
		{"unterminated quote", `remote "host`},
		{"dangling escape", `remote host\`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := privateTestDir(t)
			profile := filepath.Join(provider, "client.ovpn")
			content := test.line + "\n"
			if test.name == "dangling escape" {
				content = test.line
			}
			writePrivateTestFile(t, profile, content)
			if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err == nil {
				t.Fatalf("Inspect() accepted %q", test.line)
			}
		})
	}
}

func TestOpenVPNConfigInspectorConfinesAndValidatesSecretFiles(t *testing.T) {
	provider := privateTestDir(t)
	outside := filepath.Join(t.TempDir(), "credentials")
	writePrivateTestFile(t, outside, "secret")
	profile := filepath.Join(provider, "client.ovpn")
	writePrivateTestFile(t, profile, "auth-user-pass "+outside+"\n")
	if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside secret error = %v", err)
	}

	secret := filepath.Join(provider, "credentials")
	writePrivateTestFile(t, secret, "secret")
	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, profile, "auth-user-pass credentials\n")
	if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("permissive secret error = %v", err)
	}

	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, secret); err != nil {
		t.Fatal(err)
	}
	if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err == nil {
		t.Fatal("Inspect() accepted a symlinked secret")
	}

	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(provider, "nested")
	if err := os.Symlink(filepath.Dir(outside), nested); err != nil {
		t.Fatal(err)
	}
	writePrivateTestFile(t, profile, "auth-user-pass nested/credentials\n")
	if err := (OpenVPNConfigInspector{}).Inspect(profile, provider); err == nil {
		t.Fatal("Inspect() accepted a symlinked secret parent")
	}
}

func TestOpenVPNConfigInspectorRejectsOversizeAndOutsideProfile(t *testing.T) {
	provider := privateTestDir(t)
	outside := filepath.Join(t.TempDir(), "client.ovpn")
	writePrivateTestFile(t, outside, "client\n")
	if err := (OpenVPNConfigInspector{}).Inspect(outside, provider); err == nil {
		t.Fatal("Inspect() accepted profile outside its profile directory")
	}
	profile := filepath.Join(provider, "client.ovpn")
	writePrivateTestFile(t, profile, "client\nremote host\n")
	if err := (OpenVPNConfigInspector{MaxBytes: 8}).Inspect(profile, provider); err == nil {
		t.Fatal("Inspect() accepted oversized profile")
	}
}

func writePrivateTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
