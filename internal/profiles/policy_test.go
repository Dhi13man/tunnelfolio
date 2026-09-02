package profiles

import (
	"errors"
	"strings"
	"testing"
)

func TestWireGuardImportPolicy(t *testing.T) {
	valid := validWireGuardProfile(1)
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{name: "valid", data: valid},
		{name: "hook", data: joined(valid, "PostUp = touch /tmp/owned\n"), code: "executable_hook"},
		{name: "save config", data: joined(valid, "SaveConfig = true\n"), code: "executable_hook"},
		{name: "unknown key", data: joined(valid, "Mystery = yes\n"), code: "unsupported_key"},
		{name: "hostname dns", data: []byte(strings.ReplaceAll(string(valid), "DNS = 1.1.1.1", "DNS = resolver.example.test")), code: "invalid_dns"},
		{name: "missing peer", data: valid[:strings.Index(string(valid), "[Peer]")], code: "invalid_structure"},
		{name: "control", data: append(append([]byte(nil), valid...), 0), code: "control_character"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateWireGuardImport(test.data)
			if test.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var policyErr *PolicyError
			if !errors.As(err, &policyErr) || policyErr.Code != test.code {
				t.Fatalf("want %s, got %v", test.code, err)
			}
		})
	}
}

func TestOpenVPNImportPolicy(t *testing.T) {
	valid := validOpenVPNProfile()
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{name: "valid", data: valid},
		{name: "external key", data: joined(valid, "key private.key\n"), code: "external_reference"},
		{name: "interactive", data: joined(valid, "auth-user-pass\n"), code: "unsafe_directive"},
		{name: "script", data: joined(valid, "up /tmp/owned\n"), code: "unsafe_directive"},
		{name: "unknown", data: joined(valid, "future-option yes\n"), code: "unsupported_directive"},
		{name: "nested block", data: []byte("client\nremote x 1\n<ca>\n<key>\n</ca>\n"), code: "nested_inline_block"},
		{name: "unclosed block", data: []byte("client\nremote x 1\n<ca>\nsecret\n"), code: "unterminated_inline_block"},
		{name: "verbosity", data: joined(valid, "verb 6\n"), code: "unsafe_directive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateOpenVPNImport(test.data)
			if test.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var policyErr *PolicyError
			if !errors.As(err, &policyErr) || policyErr.Code != test.code {
				t.Fatalf("want %s, got %v", test.code, err)
			}
		})
	}
}

func FuzzImportPoliciesNeverPanic(f *testing.F) {
	f.Add(validOpenVPNProfile())
	f.Add(validWireGuardProfile(4))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidateOpenVPNImport(data)
		_, _ = ValidateWireGuardImport(data)
	})
}

func joined(prefix []byte, suffix string) []byte {
	result := append([]byte(nil), prefix...)
	return append(result, suffix...)
}
