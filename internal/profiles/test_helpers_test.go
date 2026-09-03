package profiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

var fixedTestTime = time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)

func validWireGuardProfile(seed byte) []byte {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed + 1}, 32))
	return []byte("[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.7.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = " + publicKey + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.test:51820\nPersistentKeepalive = 25\n")
}

func validOpenVPNProfile() []byte {
	return []byte("client\ndev tun\nproto udp\nremote vpn.example.test 1194\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\n<ca>\nsynthetic-ca\n</ca>\n")
}

func testProfile(t *testing.T, protocol string, data []byte, idSeed byte) Profile {
	t.Helper()
	id, err := GenerateID(bytes.NewReader(bytes.Repeat([]byte{idSeed}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ValidateImportedProfile(protocol, data)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return Profile{
		ID: id, Protocol: protocol, DisplayName: "Test profile", Group: "Tests",
		Identifier: RuntimeIdentifier(id), OriginalFilename: "test" + map[string]string{ProtocolOpenVPN: ".ovpn", ProtocolWireGuard: ".conf"}[protocol],
		ImportedAt: fixedTestTime, ContentSHA256: hex.EncodeToString(digest[:]),
		WireGuardPublicKeySHA256: policy.WireGuardPublicKeySHA256,
	}
}

func openTestStore(t *testing.T, options StoreOptions) *Store {
	t.Helper()
	if options.Root == "" {
		options.Root = t.TempDir()
	}
	if err := os.Chmod(options.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	if options.RequiredUID < 0 {
		options.RequiredUID = os.Getuid()
	}
	if options.Now == nil {
		options.Now = func() time.Time { return fixedTestTime }
	}
	store, err := OpenStore(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
