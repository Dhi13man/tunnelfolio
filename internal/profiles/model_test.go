package profiles

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestGenerateIDAndRuntimeIdentifier(t *testing.T) {
	id, err := GenerateID(bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if !idPattern.MatchString(id) {
		t.Fatalf("generated ID %q does not match contract", id)
	}
	identifier := RuntimeIdentifier(id)
	if !identifierPattern.MatchString(identifier) || len(identifier) > 15 {
		t.Fatalf("runtime identifier %q is invalid", identifier)
	}
	if identifier != RuntimeIdentifier(id) {
		t.Fatal("runtime identifier is not deterministic")
	}
}

func TestValidateMetadataReturnsSafeFieldAndCode(t *testing.T) {
	err := ValidateMetadata(Metadata{DisplayName: "Office", Group: strings.Repeat("界", 86)})
	var validation *MetadataValidationError
	if !errors.As(err, &validation) || validation.Field != "group" || validation.Code != "length_limit" || !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("metadata error = %#v", err)
	}
}

func TestValidateMetadataBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		metadata Metadata
		valid    bool
	}{
		{name: "minimum", metadata: Metadata{DisplayName: "A", Group: "B"}, valid: true},
		{name: "unicode", metadata: Metadata{DisplayName: strings.Repeat("界", 120), Group: "Work", Location: "Tokyo"}, valid: true},
		{name: "empty display", metadata: Metadata{Group: "Work"}},
		{name: "empty group", metadata: Metadata{DisplayName: "Name"}},
		{name: "control", metadata: Metadata{DisplayName: "Name\nLeak", Group: "Work"}},
		{name: "display rune overflow", metadata: Metadata{DisplayName: strings.Repeat("a", 121), Group: "Work"}},
		{name: "group rune overflow", metadata: Metadata{DisplayName: "Name", Group: strings.Repeat("a", 65)}},
		{name: "location overflow", metadata: Metadata{DisplayName: "Name", Group: "Work", Location: strings.Repeat("a", 81)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMetadata(test.metadata)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t, got %v", test.valid, err)
			}
		})
	}
}

func TestValidateEmojiMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		emoji string
		code  string
	}{
		{name: "empty"},
		{name: "flag", emoji: "🇯🇵"},
		{name: "variation selector", emoji: "✈️"},
		{name: "skin tone and joiner", emoji: "👩🏽‍💻"},
		{name: "display text", emoji: "VPN"},
		{name: "rune and byte maximum", emoji: strings.Repeat("🚀", 16)},
		{name: "rune overflow within byte limit", emoji: strings.Repeat("a", 17), code: "length_limit"},
		{name: "byte overflow", emoji: strings.Repeat("🚀", 17), code: "length_limit"},
		{name: "invalid UTF-8", emoji: "\xff", code: "invalid_utf8"},
		{name: "control", emoji: "🚀\n🚀", code: "control_character"},
		{name: "surrounding whitespace", emoji: " 🚀", code: "surrounding_whitespace"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMetadata(Metadata{DisplayName: "Office", Group: "Work", Emoji: test.emoji})
			if test.code == "" {
				if err != nil {
					t.Fatalf("valid emoji rejected: %v", err)
				}
				return
			}
			var validation *MetadataValidationError
			if !errors.As(err, &validation) || validation.Field != "emoji" || validation.Code != test.code || !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("emoji error = %#v, want %s", err, test.code)
			}
		})
	}
}

func TestValidateManifestRejectsCrossReferencesAndDuplicates(t *testing.T) {
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 1)
	tests := []Manifest{
		{Version: 99, StartupMode: StartupManual},
		{Version: ManifestVersion, StartupMode: "automatic"},
		{Version: ManifestVersion, StartupMode: StartupManual, Profiles: []Profile{profile, profile}},
		{Version: ManifestVersion, StartupMode: StartupManual, Profiles: []Profile{profile}, Favorites: []string{"tf_aaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{Version: ManifestVersion, StartupMode: StartupManual, Profiles: []Profile{profile}, DesiredProfile: "tf_aaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for index, manifest := range tests {
		if err := ValidateManifest(manifest); err == nil {
			t.Fatalf("case %d unexpectedly passed", index)
		}
	}
}
