package profiles

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ProtocolOpenVPN   = "openvpn"
	ProtocolWireGuard = "wireguard"

	StartupManual  = "manual"
	StartupRestore = "restore"

	ManifestVersion     = 1
	MaxProfiles         = 100
	MaxRecents          = 5
	MaxProfileBytes     = 1 << 20
	MaxDisplayNameRunes = 120
	MaxDisplayNameBytes = 512
	MaxGroupRunes       = 64
	MaxGroupBytes       = 256
	MaxLocationRunes    = 80
	MaxLocationBytes    = 320
)

var (
	idPattern         = regexp.MustCompile(`^tf_[a-z2-7]{26}$`)
	identifierPattern = regexp.MustCompile(`^tf[a-z2-7]{12}$`)
	base32NoPadding   = base32.StdEncoding.WithPadding(base32.NoPadding)

	ErrNotFound          = errors.New("profile not found")
	ErrCapacity          = errors.New("profile capacity reached")
	ErrConflict          = errors.New("profile store conflict")
	ErrOutcomeAmbiguous  = errors.New("profile store outcome is ambiguous")
	ErrInvalidManifest   = errors.New("invalid profile manifest")
	ErrCleanupPending    = errors.New("profile removed with cleanup pending")
	ErrReadOnly          = errors.New("profile store is read-only")
	ErrStaleInspection   = errors.New("import inspection is stale")
	ErrInvalidReceipt    = errors.New("import inspection receipt is invalid")
	ErrExpiredReceipt    = errors.New("import inspection receipt expired")
	ErrImportBusy        = errors.New("another import is in progress")
	ErrPolicyRejected    = errors.New("profile import policy rejected the file")
	ErrProtocolAmbiguous = errors.New("profile protocol is ambiguous")
	ErrInvalidMetadata   = errors.New("invalid profile metadata")
)

type Profile struct {
	ID                       string    `json:"id"`
	Protocol                 string    `json:"protocol"`
	DisplayName              string    `json:"display_name"`
	Group                    string    `json:"group"`
	Location                 string    `json:"location,omitempty"`
	Identifier               string    `json:"identifier"`
	OriginalFilename         string    `json:"original_filename"`
	ImportedAt               time.Time `json:"imported_at"`
	ContentSHA256            string    `json:"content_sha256"`
	WireGuardPublicKeySHA256 string    `json:"wireguard_public_key_sha256,omitempty"`
}

type Manifest struct {
	Version         int       `json:"version"`
	LibraryRevision uint64    `json:"library_revision"`
	Profiles        []Profile `json:"profiles"`
	Favorites       []string  `json:"favorites"`
	Recents         []string  `json:"recents"`
	StartupMode     string    `json:"startup_mode"`
	DesiredProfile  string    `json:"desired_profile,omitempty"`
	ConnectedAt     int64     `json:"connected_at,omitempty"`
}

type Metadata struct {
	DisplayName string
	Group       string
	Location    string
}

type MetadataValidationError struct {
	Field string
	Code  string
}

func (e *MetadataValidationError) Error() string { return "invalid " + e.Field }
func (e *MetadataValidationError) Unwrap() error { return ErrInvalidMetadata }

type MetadataPatch struct {
	DisplayName   *string
	Group         *string
	Location      *string
	ClearLocation bool
}

func InitialManifest() Manifest {
	return Manifest{
		Version:     ManifestVersion,
		Profiles:    []Profile{},
		Favorites:   []string{},
		Recents:     []string{},
		StartupMode: StartupManual,
	}
}

func (m Manifest) Clone() Manifest {
	clone := m
	clone.Profiles = append([]Profile{}, m.Profiles...)
	clone.Favorites = append([]string{}, m.Favorites...)
	clone.Recents = append([]string{}, m.Recents...)
	return clone
}

func (m Manifest) Profile(id string) (Profile, bool) {
	for _, profile := range m.Profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func ValidateManifest(manifest Manifest) error {
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidManifest, manifest.Version)
	}
	if len(manifest.Profiles) > MaxProfiles {
		return fmt.Errorf("%w: more than %d profiles", ErrInvalidManifest, MaxProfiles)
	}
	if manifest.StartupMode != StartupManual && manifest.StartupMode != StartupRestore {
		return fmt.Errorf("%w: invalid startup mode", ErrInvalidManifest)
	}
	if manifest.ConnectedAt < 0 {
		return fmt.Errorf("%w: invalid connected time", ErrInvalidManifest)
	}
	ids := make(map[string]struct{}, len(manifest.Profiles))
	identifiers := make(map[string]struct{}, len(manifest.Profiles))
	contents := make(map[string]struct{}, len(manifest.Profiles))
	for index, profile := range manifest.Profiles {
		if err := ValidateProfile(profile); err != nil {
			return fmt.Errorf("%w: profile %d: %v", ErrInvalidManifest, index, err)
		}
		if _, exists := ids[profile.ID]; exists {
			return fmt.Errorf("%w: duplicate profile ID", ErrInvalidManifest)
		}
		if _, exists := identifiers[profile.Identifier]; exists {
			return fmt.Errorf("%w: duplicate runtime identifier", ErrInvalidManifest)
		}
		if _, exists := contents[profile.ContentSHA256]; exists {
			return fmt.Errorf("%w: duplicate profile content", ErrInvalidManifest)
		}
		ids[profile.ID] = struct{}{}
		identifiers[profile.Identifier] = struct{}{}
		contents[profile.ContentSHA256] = struct{}{}
	}
	if err := validateIDList(manifest.Favorites, MaxProfiles, ids); err != nil {
		return fmt.Errorf("%w: favorites: %v", ErrInvalidManifest, err)
	}
	if err := validateIDList(manifest.Recents, MaxRecents, ids); err != nil {
		return fmt.Errorf("%w: recents: %v", ErrInvalidManifest, err)
	}
	if manifest.DesiredProfile != "" {
		if _, exists := ids[manifest.DesiredProfile]; !exists {
			return fmt.Errorf("%w: desired profile does not exist", ErrInvalidManifest)
		}
	}
	return nil
}

func ValidateProfile(profile Profile) error {
	if !idPattern.MatchString(profile.ID) {
		return errors.New("invalid profile ID")
	}
	if !ValidProtocol(profile.Protocol) {
		return errors.New("invalid protocol")
	}
	if err := ValidateMetadata(Metadata{DisplayName: profile.DisplayName, Group: profile.Group, Location: profile.Location}); err != nil {
		return err
	}
	if !identifierPattern.MatchString(profile.Identifier) {
		return errors.New("invalid runtime identifier")
	}
	if err := ValidateOriginalFilename(profile.OriginalFilename); err != nil {
		return err
	}
	if profile.ImportedAt.IsZero() || profile.ImportedAt.Location() != time.UTC {
		return errors.New("invalid import time")
	}
	if !validSHA256(profile.ContentSHA256) {
		return errors.New("invalid content fingerprint")
	}
	if profile.Protocol == ProtocolWireGuard {
		if !validSHA256(profile.WireGuardPublicKeySHA256) {
			return errors.New("invalid WireGuard identity fingerprint")
		}
	} else if profile.WireGuardPublicKeySHA256 != "" {
		return errors.New("OpenVPN profile has WireGuard identity")
	}
	return nil
}

func ValidateMetadata(metadata Metadata) error {
	if code := validateText(metadata.DisplayName, 1, MaxDisplayNameRunes, MaxDisplayNameBytes); code != "" {
		return &MetadataValidationError{Field: "display_name", Code: code}
	}
	if code := validateText(metadata.Group, 1, MaxGroupRunes, MaxGroupBytes); code != "" {
		return &MetadataValidationError{Field: "group", Code: code}
	}
	if metadata.Location != "" {
		if code := validateText(metadata.Location, 1, MaxLocationRunes, MaxLocationBytes); code != "" {
			return &MetadataValidationError{Field: "location", Code: code}
		}
	}
	return nil
}

func ValidateOriginalFilename(name string) error {
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return errors.New("invalid original filename")
	}
	if !utf8.ValidString(name) {
		return errors.New("original filename is not valid UTF-8")
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return errors.New("original filename contains a control character")
		}
	}
	return nil
}

func ValidProtocol(protocol string) bool {
	return protocol == ProtocolOpenVPN || protocol == ProtocolWireGuard
}

func GenerateID(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var raw [16]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return "", err
	}
	return "tf_" + strings.ToLower(base32NoPadding.EncodeToString(raw[:])), nil
}

func RuntimeIdentifier(id string) string {
	digest := sha256.Sum256([]byte(id))
	return "tf" + strings.ToLower(base32NoPadding.EncodeToString(digest[:]))[:12]
}

func SortedProfiles(values []Profile) []Profile {
	result := append([]Profile(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		left := strings.ToLower(result[i].DisplayName)
		right := strings.ToLower(result[j].DisplayName)
		if left == right {
			return result[i].ID < result[j].ID
		}
		return left < right
	})
	return result
}

func validateText(value string, minRunes, maxRunes, maxBytes int) string {
	if !utf8.ValidString(value) {
		return "invalid_utf8"
	}
	if strings.TrimSpace(value) != value {
		return "surrounding_whitespace"
	}
	runes := utf8.RuneCountInString(value)
	if runes < minRunes {
		return "required"
	}
	if runes > maxRunes || len(value) > maxBytes {
		return "length_limit"
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return "control_character"
		}
	}
	return ""
}

func validateIDList(values []string, limit int, ids map[string]struct{}) error {
	if len(values) > limit {
		return fmt.Errorf("more than %d values", limit)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := ids[value]; !exists {
			return errors.New("unknown profile ID")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("duplicate profile ID")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}
