package profiles

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
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

func FuzzValidateMetadataNeverPanics(f *testing.F) {
	f.Add("Japan", "Mullvad", "Tokyo")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, name, group, location string) {
		_ = ValidateMetadata(Metadata{DisplayName: name, Group: group, Location: location})
		if utf8.ValidString(name) && len(name) <= MaxDisplayNameBytes {
			_ = name
		}
	})
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
