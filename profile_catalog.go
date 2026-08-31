package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

const (
	BackendOpenVPN   = "openvpn"
	BackendWireGuard = "wireguard"
)

var (
	providerSegmentPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	openVPNIdentifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	wireGuardIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)

	ErrBackendUnavailable = errors.New("backend unavailable")
	ErrProfileNotFound    = errors.New("profile not found")
)

type CatalogProfile struct {
	ID          string `json:"id"`
	Backend     string `json:"backend"`
	Provider    string `json:"provider"`
	Identifier  string `json:"-"`
	Name        string `json:"name"`
	Path        string `json:"-"`
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	Region      string `json:"region,omitempty"`
	Flag        string `json:"flag,omitempty"`
}

type ProfileCatalog struct {
	root        string
	requiredUID int
}

func NewProfileCatalog(root string) (*ProfileCatalog, error) {
	return newProfileCatalog(root, 0)
}

func newProfileCatalog(root string, requiredUID int) (*ProfileCatalog, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve profile root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve profile root links: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(abs) {
		return nil, errors.New("profile root path must not contain symlinks")
	}
	catalog := &ProfileCatalog{root: filepath.Clean(abs), requiredUID: requiredUID}
	fd, err := openSecureDirectory(catalog.root, requiredUID)
	if err != nil {
		return nil, fmt.Errorf("validate profile root: %w", err)
	}
	_ = syscall.Close(fd)
	return catalog, nil
}

func (c *ProfileCatalog) Profiles(backend string) ([]CatalogProfile, error) {
	if !validBackend(backend) {
		return nil, fmt.Errorf("%w: %q", ErrBackendUnavailable, backend)
	}

	backendPath := filepath.Join(c.root, backend)
	backendFD, err := openSecureDirectory(backendPath, c.requiredUID)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s profile directory is absent", ErrBackendUnavailable, backend)
	}
	if err != nil {
		return nil, fmt.Errorf("validate %s profile directory: %w", backend, err)
	}
	backendDirectory := os.NewFile(uintptr(backendFD), "backend-profile-directory")
	defer backendDirectory.Close()

	providers, err := backendDirectory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s providers: %w", backend, err)
	}
	profiles := make([]CatalogProfile, 0)
	seenIDs := make(map[string]struct{})
	for _, providerEntry := range providers {
		provider := providerEntry.Name()
		if !providerSegmentPattern.MatchString(provider) {
			return nil, fmt.Errorf("invalid provider directory %q", provider)
		}
		providerPath := filepath.Join(backendPath, provider)
		providerFD, err := openSecureDirectory(providerPath, c.requiredUID)
		if err != nil {
			return nil, fmt.Errorf("validate provider %q: %w", provider, err)
		}
		providerDirectory := os.NewFile(uintptr(providerFD), "provider-profile-directory")

		providerProfiles, listErr := c.profilesInProvider(backend, provider, providerPath, providerDirectory)
		_ = providerDirectory.Close()
		if listErr != nil {
			return nil, listErr
		}
		for _, profile := range providerProfiles {
			if _, exists := seenIDs[profile.ID]; exists {
				return nil, fmt.Errorf("duplicate profile ID %q", profile.ID)
			}
			seenIDs[profile.ID] = struct{}{}
			profiles = append(profiles, profile)
		}
	}

	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles, nil
}

func (c *ProfileCatalog) Resolve(id string) (CatalogProfile, error) {
	backend, provider, identifier, ok := splitProfileID(id)
	if !ok {
		return CatalogProfile{}, ErrProfileNotFound
	}
	profiles, err := c.Profiles(backend)
	if err != nil {
		return CatalogProfile{}, err
	}
	for _, profile := range profiles {
		if profile.Provider == provider && profile.Identifier == identifier {
			return profile, nil
		}
	}
	return CatalogProfile{}, ErrProfileNotFound
}

func (c *ProfileCatalog) profilesInProvider(backend, provider, providerPath string, providerDirectory *os.File) ([]CatalogProfile, error) {
	entries, err := providerDirectory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list provider %q: %w", provider, err)
	}
	profiles := make([]CatalogProfile, 0, len(entries))
	for _, entry := range entries {
		identifier, accepted := profileIdentifier(backend, entry.Name())
		if !accepted {
			continue
		}
		if err := validateSecureFileAt(int(providerDirectory.Fd()), entry.Name(), c.requiredUID); err != nil {
			return nil, fmt.Errorf("validate profile %s/%s/%s: %w", backend, provider, identifier, err)
		}
		profile := CatalogProfile{
			ID:         strings.Join([]string{backend, provider, identifier}, "/"),
			Backend:    backend,
			Provider:   provider,
			Identifier: identifier,
			Name:       identifier,
			Path:       filepath.Join(providerPath, entry.Name()),
		}
		if provider == "mullvad" {
			enrichMullvadProfile(&profile)
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func profileIdentifier(backend, filename string) (string, bool) {
	extension := filepath.Ext(filename)
	identifier := strings.TrimSuffix(filename, extension)
	switch backend {
	case BackendWireGuard:
		return identifier, extension == ".conf" && wireGuardIdentifierPattern.MatchString(identifier)
	case BackendOpenVPN:
		return identifier, (extension == ".ovpn" || extension == ".conf") && openVPNIdentifierPattern.MatchString(identifier)
	default:
		return "", false
	}
}

func splitProfileID(id string) (backend, provider, identifier string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || !validBackend(parts[0]) || !providerSegmentPattern.MatchString(parts[1]) {
		return "", "", "", false
	}
	pattern := openVPNIdentifierPattern
	if parts[0] == BackendWireGuard {
		pattern = wireGuardIdentifierPattern
	}
	if !pattern.MatchString(parts[2]) {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func validBackend(backend string) bool {
	return backend == BackendOpenVPN || backend == BackendWireGuard
}

func openSecureDirectory(path string, requiredUID int) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	if err := validateDescriptor(fd, syscall.S_IFDIR, 0o700, requiredUID); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validateSecureFileAt(directoryFD int, name string, requiredUID int) error {
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return validateDescriptor(fd, syscall.S_IFREG, 0o600, requiredUID)
}

func validateDescriptor(fd int, expectedType uint32, expectedMode uint32, requiredUID int) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&syscall.S_IFMT != expectedType {
		return errors.New("unexpected file type")
	}
	if stat.Mode&0o777 != expectedMode {
		return fmt.Errorf("permissions %04o, require %04o", stat.Mode&0o777, expectedMode)
	}
	if int(stat.Uid) != requiredUID {
		return fmt.Errorf("owner uid %d, require %d", stat.Uid, requiredUID)
	}
	return nil
}

func enrichMullvadProfile(profile *CatalogProfile) {
	code := strings.ToLower(strings.TrimPrefix(profile.Identifier, "mullvad_"))
	if len(code) > 2 {
		code = code[:2]
	}
	country, ok := mullvadCountries[code]
	if !ok {
		return
	}
	profile.Name = country.name
	profile.CountryCode = code
	profile.CountryName = country.name
	profile.Region = country.region
	profile.Flag = countryFlagFor(code)
}

func countryFlagFor(code string) string {
	if len(code) != 2 || code[0] < 'a' || code[0] > 'z' || code[1] < 'a' || code[1] > 'z' {
		return ""
	}
	return string([]rune{rune(code[0]-'a') + 0x1F1E6, rune(code[1]-'a') + 0x1F1E6})
}

type mullvadCountry struct {
	name   string
	region string
}

var mullvadCountries = map[string]mullvadCountry{
	"al": {"Albania", "Europe"}, "ar": {"Argentina", "Americas"}, "at": {"Austria", "Europe"},
	"au": {"Australia", "Oceania"}, "be": {"Belgium", "Europe"}, "bg": {"Bulgaria", "Europe"},
	"br": {"Brazil", "Americas"}, "ca": {"Canada", "Americas"}, "ch": {"Switzerland", "Europe"},
	"cl": {"Chile", "Americas"}, "co": {"Colombia", "Americas"}, "cy": {"Cyprus", "Europe"},
	"cz": {"Czech Republic", "Europe"}, "de": {"Germany", "Europe"}, "dk": {"Denmark", "Europe"},
	"ee": {"Estonia", "Europe"}, "es": {"Spain", "Europe"}, "fi": {"Finland", "Europe"},
	"fr": {"France", "Europe"}, "gb": {"United Kingdom", "Europe"}, "gr": {"Greece", "Europe"},
	"hk": {"Hong Kong", "Asia"}, "hr": {"Croatia", "Europe"}, "hu": {"Hungary", "Europe"},
	"id": {"Indonesia", "Asia"}, "ie": {"Ireland", "Europe"}, "il": {"Israel", "Asia"},
	"it": {"Italy", "Europe"}, "jp": {"Japan", "Asia"}, "mx": {"Mexico", "Americas"},
	"my": {"Malaysia", "Asia"}, "ng": {"Nigeria", "Africa"}, "nl": {"Netherlands", "Europe"},
	"no": {"Norway", "Europe"}, "nz": {"New Zealand", "Oceania"}, "pe": {"Peru", "Americas"},
	"ph": {"Philippines", "Asia"}, "pl": {"Poland", "Europe"}, "pt": {"Portugal", "Europe"},
	"ro": {"Romania", "Europe"}, "rs": {"Serbia", "Europe"}, "se": {"Sweden", "Europe"},
	"sg": {"Singapore", "Asia"}, "si": {"Slovenia", "Europe"}, "sk": {"Slovakia", "Europe"},
	"th": {"Thailand", "Asia"}, "tr": {"Turkey", "Europe"}, "ua": {"Ukraine", "Europe"},
	"us": {"United States", "Americas"}, "za": {"South Africa", "Africa"},
}
