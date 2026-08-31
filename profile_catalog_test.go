package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestProfileCatalogDiscoversStableProfilesAndMetadata(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "home.conf")
	writeCatalogProfile(t, root, BackendWireGuard, "mullvad", "mullvad_de.conf")
	writeCatalogProfile(t, root, BackendOpenVPN, "nordvpn", "uk.london.ovpn")
	writeCatalogProfile(t, root, BackendOpenVPN, "generic", "office.conf")

	catalog := testCatalog(t, root)
	wireGuard, err := catalog.Profiles(BackendWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	if len(wireGuard) != 2 {
		t.Fatalf("WireGuard profiles = %d, want 2", len(wireGuard))
	}
	if got := wireGuard[0].ID; got != "wireguard/generic/home" {
		t.Fatalf("first stable ID = %q", got)
	}
	mullvad := wireGuard[1]
	if mullvad.ID != "wireguard/mullvad/mullvad_de" || mullvad.CountryCode != "de" || mullvad.CountryName != "Germany" || mullvad.Region != "Europe" || mullvad.Flag != "🇩🇪" {
		t.Fatalf("Mullvad metadata = %+v", mullvad)
	}

	openVPN, err := catalog.Profiles(BackendOpenVPN)
	if err != nil {
		t.Fatal(err)
	}
	if len(openVPN) != 2 || openVPN[0].ID != "openvpn/generic/office" || openVPN[1].ID != "openvpn/nordvpn/uk.london" {
		t.Fatalf("OpenVPN profiles = %+v", openVPN)
	}

	resolved, err := catalog.Resolve("openvpn/nordvpn/uk.london")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Path != filepath.Join(root, BackendOpenVPN, "nordvpn", "uk.london.ovpn") {
		t.Fatalf("resolved path = %q", resolved.Path)
	}
}

func TestProfileCatalogBackendsAreIndependent(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "home.conf")
	catalog := testCatalog(t, root)

	profiles, err := catalog.Profiles(BackendWireGuard)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("WireGuard discovery = %+v, %v", profiles, err)
	}
	if _, err := catalog.Profiles(BackendOpenVPN); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("missing OpenVPN error = %v", err)
	}
}

func TestProfileCatalogRejectsUnsafeHierarchy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{
			name: "root mode",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(root, 0o750); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "backend mode",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, BackendWireGuard), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "provider mode",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, BackendWireGuard, "generic"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "profile mode",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, BackendWireGuard, "generic", "home.conf"), 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "profile symlink",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				profile := filepath.Join(root, BackendWireGuard, "generic", "home.conf")
				if err := os.Remove(profile); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", profile); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "profile fifo",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				profile := filepath.Join(root, BackendWireGuard, "generic", "home.conf")
				if err := os.Remove(profile); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(profile, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := secureCatalogRoot(t)
			writeCatalogProfile(t, root, BackendWireGuard, "generic", "home.conf")
			test.mutate(t, root)
			catalog, err := newProfileCatalog(root, os.Geteuid())
			if test.name == "root mode" {
				if err == nil {
					t.Fatal("unsafe root was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := catalog.Profiles(BackendWireGuard); err == nil {
				t.Fatal("unsafe catalog entry was accepted")
			}
		})
	}
}

func TestProfileCatalogRejectsSymlinkedProvider(t *testing.T) {
	root := secureCatalogRoot(t)
	if err := os.Mkdir(filepath.Join(root, BackendWireGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, BackendWireGuard, "generic")); err != nil {
		t.Fatal(err)
	}
	catalog := testCatalog(t, root)
	if _, err := catalog.Profiles(BackendWireGuard); err == nil {
		t.Fatal("symlinked provider was accepted")
	}
}

func TestProfileCatalogRejectsSymlinkedRootAndWrongOwner(t *testing.T) {
	root := secureCatalogRoot(t)
	link := filepath.Join(t.TempDir(), "profiles-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newProfileCatalog(link, os.Geteuid()); err == nil {
		t.Fatal("symlinked root was accepted")
	}
	if _, err := openSecureDirectory(root, os.Geteuid()+1); err == nil {
		t.Fatal("directory with a different required owner was accepted")
	}
}

func TestProfileCatalogRejectsOpenedFileWithWrongOwner(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "home.conf")
	providerFD, err := syscall.Open(filepath.Join(root, BackendWireGuard, "generic"), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(providerFD)
	if err := validateSecureFileAt(providerFD, "home.conf", os.Geteuid()+1); err == nil {
		t.Fatal("profile with a different required owner was accepted")
	}
}

func TestProfileCatalogRejectsDuplicateStableID(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendOpenVPN, "generic", "office.conf")
	writeCatalogProfile(t, root, BackendOpenVPN, "generic", "office.ovpn")
	catalog := testCatalog(t, root)
	if _, err := catalog.Profiles(BackendOpenVPN); err == nil || !strings.Contains(err.Error(), "duplicate profile ID") {
		t.Fatalf("duplicate ID error = %v", err)
	}
}

func TestProfileCatalogAppliesIdentifierGrammars(t *testing.T) {
	root := secureCatalogRoot(t)
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "123456789012345.conf")
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "1234567890123456.conf")
	writeCatalogProfile(t, root, BackendWireGuard, "generic", "ignored.ovpn")
	writeCatalogProfile(t, root, BackendOpenVPN, "generic", "valid_name-1.ovpn")
	writeCatalogProfile(t, root, BackendOpenVPN, "generic", "bad name.ovpn")

	catalog := testCatalog(t, root)
	wireGuard, err := catalog.Profiles(BackendWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	if len(wireGuard) != 1 || wireGuard[0].Identifier != "123456789012345" {
		t.Fatalf("WireGuard grammar result = %+v", wireGuard)
	}
	openVPN, err := catalog.Profiles(BackendOpenVPN)
	if err != nil {
		t.Fatal(err)
	}
	if len(openVPN) != 1 || openVPN[0].Identifier != "valid_name-1" {
		t.Fatalf("OpenVPN grammar result = %+v", openVPN)
	}
	for _, id := range []string{"wireguard/generic/../escape", "wireguard/Bad/home", "wireguard/generic/1234567890123456", "unknown/generic/home"} {
		if _, err := catalog.Resolve(id); !errors.Is(err, ErrProfileNotFound) {
			t.Fatalf("Resolve(%q) error = %v", id, err)
		}
	}
}

func secureCatalogRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("catalog descriptor policy is Linux-specific")
	}
	root := filepath.Join(t.TempDir(), "profiles")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeCatalogProfile(t *testing.T, root, backend, provider, filename string) string {
	t.Helper()
	directory := filepath.Join(root, backend, provider)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, backend), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, filename)
	if err := os.WriteFile(path, []byte("test profile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCatalog(t *testing.T, root string) *ProfileCatalog {
	t.Helper()
	catalog, err := newProfileCatalog(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
