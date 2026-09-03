package profiles

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxImportFiles   = 100
	MaxImportRequest = 32 << 20
	receiptVersion   = 1
	receiptTTL       = time.Hour
)

type ImportFile struct {
	Name             string
	Bytes            []byte
	ProtocolOverride string
}

type InspectionRecord struct {
	Ordinal     int           `json:"ordinal"`
	ID          string        `json:"id,omitempty"`
	Protocol    string        `json:"protocol,omitempty"`
	Identifier  string        `json:"identifier,omitempty"`
	Disposition string        `json:"disposition,omitempty"`
	Issues      []PolicyIssue `json:"issues"`

	digest                   string
	wireGuardPublicKeyDigest string
	protocolOverride         string
}

type MetadataSuggestion struct {
	Ordinal     int    `json:"ordinal"`
	DisplayName string `json:"display_name"`
	Group       string `json:"group"`
	Location    string `json:"location,omitempty"`
}

type Inspection struct {
	LibraryRevision   uint64               `json:"library_revision"`
	InspectionRecords []InspectionRecord   `json:"inspection_records"`
	Suggestions       []MetadataSuggestion `json:"suggestions"`
	Receipt           string               `json:"receipt,omitempty"`
	ExpiresAt         *time.Time           `json:"expires_at,omitempty"`
	CommitReady       bool                 `json:"commit_ready"`
}

type CommitRequest struct {
	Files              []ImportFile
	LibraryRevision    uint64
	InspectionRecords  []InspectionRecord
	Metadata           map[int]Metadata
	Receipt            string
	TrustProfilePolicy bool
}

type ImportMetadataError struct {
	File int
	Err  error
}

func (e *ImportMetadataError) Error() string {
	return fmt.Sprintf("file %d metadata is invalid", e.File)
}
func (e *ImportMetadataError) Unwrap() error { return e.Err }

type ImportResult struct {
	Ordinal int
	Result  string
	Profile Profile
}

type CommitResult struct {
	Records  []ImportResult
	Replayed bool
	Revision uint64
}

type CompatibilityChecker interface {
	CheckWireGuard([]byte) error
}

type CompatibilityCheckFunc func([]byte) error

func (function CompatibilityCheckFunc) CheckWireGuard(data []byte) error { return function(data) }

type ImportServiceOptions struct {
	Store                *Store
	Random               io.Reader
	Now                  func() time.Time
	WireGuardChecker     CompatibilityChecker
	RuntimeNameAvailable func(string) (bool, error)
	CommitAdmission      func() (func(), error)
}

type ImportService struct {
	store                *Store
	random               io.Reader
	now                  func() time.Time
	checker              CompatibilityChecker
	runtimeNameAvailable func(string) (bool, error)
	commitAdmission      func() (func(), error)
	key                  [32]byte
	gate                 chan struct{}
}

func NewImportService(options ImportServiceOptions) (*ImportService, error) {
	if options.Store == nil {
		return nil, errors.New("profile store is required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.WireGuardChecker == nil {
		return nil, errors.New("WireGuard compatibility checker is required")
	}
	service := &ImportService{
		store:                options.Store,
		random:               options.Random,
		now:                  options.Now,
		checker:              options.WireGuardChecker,
		runtimeNameAvailable: options.RuntimeNameAvailable,
		commitAdmission:      options.CommitAdmission,
		gate:                 make(chan struct{}, 1),
	}
	if _, err := io.ReadFull(service.random, service.key[:]); err != nil {
		return nil, fmt.Errorf("generate import receipt key: %w", err)
	}
	service.gate <- struct{}{}
	return service, nil
}

func (s *ImportService) Inspect(files []ImportFile) (Inspection, error) {
	if !s.acquire() {
		return Inspection{}, ErrImportBusy
	}
	defer s.release()
	if err := validateImportEnvelope(files); err != nil {
		return Inspection{}, err
	}
	manifest := s.store.Snapshot()
	inspection := Inspection{
		LibraryRevision:   manifest.LibraryRevision,
		InspectionRecords: make([]InspectionRecord, len(files)),
		Suggestions:       make([]MetadataSuggestion, len(files)),
		CommitReady:       true,
	}
	byDigest := make(map[string]Profile, len(manifest.Profiles)+len(files))
	identifiers := make(map[string]struct{}, len(manifest.Profiles)+len(files))
	for _, profile := range manifest.Profiles {
		byDigest[profile.ContentSHA256] = profile
		identifiers[profile.Identifier] = struct{}{}
	}
	for ordinal, file := range files {
		record := InspectionRecord{Ordinal: ordinal, Issues: []PolicyIssue{}}
		record.protocolOverride = file.ProtocolOverride
		inspection.Suggestions[ordinal] = MetadataSuggestion{
			Ordinal: ordinal, DisplayName: suggestedDisplayName(file.Name), Group: "Unsorted",
		}
		if err := ValidateOriginalFilename(file.Name); err != nil {
			record.Issues = append(record.Issues, issue("file", "invalid_filename", "The filename must be valid UTF-8 without path separators or control characters."))
			inspection.CommitReady = false
			inspection.InspectionRecords[ordinal] = record
			continue
		}
		digest := sha256.Sum256(file.Bytes)
		record.digest = hex.EncodeToString(digest[:])
		protocol, protocolIssue := detectProtocol(file)
		if protocolIssue != nil {
			record.Issues = append(record.Issues, *protocolIssue)
			inspection.CommitReady = false
			inspection.InspectionRecords[ordinal] = record
			continue
		}
		record.Protocol = protocol
		policy, err := ValidateImportedProfile(protocol, file.Bytes)
		if err != nil {
			record.Issues = append(record.Issues, policyIssue(err))
			inspection.CommitReady = false
			inspection.InspectionRecords[ordinal] = record
			continue
		}
		if protocol == ProtocolWireGuard {
			if err := s.checker.CheckWireGuard(file.Bytes); err != nil {
				record.Issues = append(record.Issues, issue("file", "wg_quick_incompatible", "The installed WireGuard tooling did not accept this profile."))
				inspection.CommitReady = false
				inspection.InspectionRecords[ordinal] = record
				continue
			}
			record.wireGuardPublicKeyDigest = policy.WireGuardPublicKeySHA256
		}
		if existing, found := byDigest[record.digest]; found {
			record.ID = existing.ID
			record.Protocol = existing.Protocol
			record.Identifier = existing.Identifier
			record.wireGuardPublicKeyDigest = existing.WireGuardPublicKeySHA256
			record.Disposition = "already_imported"
			inspection.InspectionRecords[ordinal] = record
			continue
		}
		id, identifier, err := s.generateIdentity(protocol, identifiers)
		if err != nil {
			return Inspection{}, err
		}
		record.ID = id
		record.Identifier = identifier
		record.Disposition = "new"
		identifiers[identifier] = struct{}{}
		byDigest[record.digest] = Profile{
			ID: id, Protocol: protocol, Identifier: identifier, ContentSHA256: record.digest,
			WireGuardPublicKeySHA256: record.wireGuardPublicKeyDigest,
		}
		inspection.InspectionRecords[ordinal] = record
	}
	if inspection.CommitReady {
		expiresAt := s.now().UTC().Add(receiptTTL).Truncate(time.Second)
		inspection.ExpiresAt = &expiresAt
		inspection.Receipt = s.sign(inspection.LibraryRevision, expiresAt, inspection.InspectionRecords)
	}
	return inspection, nil
}

func (s *ImportService) Commit(request CommitRequest) (CommitResult, error) {
	if !s.acquire() {
		return CommitResult{}, ErrImportBusy
	}
	defer s.release()
	if !request.TrustProfilePolicy {
		return CommitResult{}, errors.New("profile policy trust acknowledgement is required")
	}
	if s.commitAdmission != nil {
		release, err := s.commitAdmission()
		if err != nil {
			return CommitResult{}, err
		}
		if release == nil {
			return CommitResult{}, errors.New("commit admission returned no release function")
		}
		defer release()
	}
	if err := validateImportEnvelope(request.Files); err != nil {
		return CommitResult{}, err
	}
	if len(request.InspectionRecords) != len(request.Files) {
		return CommitResult{}, ErrInvalidReceipt
	}
	if len(request.Metadata) != len(request.Files) {
		return CommitResult{}, errors.New("metadata must contain exactly one record per file")
	}
	for ordinal := range request.Files {
		metadata, found := request.Metadata[ordinal]
		if !found {
			return CommitResult{}, fmt.Errorf("file %d metadata is required", ordinal)
		}
		if err := ValidateMetadata(metadata); err != nil {
			return CommitResult{}, &ImportMetadataError{File: ordinal, Err: err}
		}
	}
	expiry, signature, err := decodeReceipt(request.Receipt)
	if err != nil {
		return CommitResult{}, err
	}
	if s.now().UTC().After(expiry) {
		return CommitResult{}, ErrExpiredReceipt
	}
	records, err := s.reinspectBound(request.Files, request.InspectionRecords)
	if err != nil {
		return CommitResult{}, err
	}
	expected := s.receiptMAC(request.LibraryRevision, expiry, records)
	if !hmac.Equal(signature, expected) {
		return CommitResult{}, ErrInvalidReceipt
	}
	manifest := s.store.Snapshot()
	if manifest.LibraryRevision != request.LibraryRevision {
		if err := s.store.RepairDurability(); err != nil {
			return CommitResult{}, err
		}
		manifest = s.store.Snapshot()
		if replay, ok := exactReplay(manifest, records); ok {
			return CommitResult{Records: replay, Replayed: true, Revision: manifest.LibraryRevision}, nil
		}
		return CommitResult{}, ErrStaleInspection
	}
	objects := make([]NewObject, 0, len(records))
	planned := make(map[string]Profile, len(records))
	for index, record := range records {
		if existing, found := manifest.Profile(record.ID); found {
			if record.Disposition != "already_imported" || !recordMatchesProfile(record, existing) {
				return CommitResult{}, ErrStaleInspection
			}
			planned[record.ID] = existing
			continue
		}
		if record.Disposition == "already_imported" {
			if prior, found := planned[record.ID]; found && recordMatchesProfile(record, prior) {
				continue
			}
			return CommitResult{}, ErrStaleInspection
		}
		metadata := request.Metadata[index]
		profile := Profile{
			ID: record.ID, Protocol: record.Protocol, DisplayName: metadata.DisplayName,
			Group: metadata.Group, Location: metadata.Location, Identifier: record.Identifier,
			OriginalFilename: request.Files[index].Name, ImportedAt: s.now().UTC(),
			ContentSHA256: record.digest, WireGuardPublicKeySHA256: record.wireGuardPublicKeyDigest,
		}
		objects = append(objects, NewObject{Profile: profile, Bytes: request.Files[index].Bytes})
		planned[record.ID] = profile
	}
	publication, err := s.store.Publish(request.LibraryRevision, objects)
	if err != nil {
		return CommitResult{}, err
	}
	result := CommitResult{Records: make([]ImportResult, len(records)), Revision: publication.Manifest.LibraryRevision}
	for index, record := range records {
		profile, found := publication.Manifest.Profile(record.ID)
		if !found {
			profile = planned[record.ID]
		}
		outcome := "imported"
		if record.Disposition == "already_imported" {
			outcome = "already_imported"
		}
		result.Records[index] = ImportResult{Ordinal: index, Result: outcome, Profile: profile}
	}
	return result, nil
}

func (s *ImportService) reinspectBound(files []ImportFile, supplied []InspectionRecord) ([]InspectionRecord, error) {
	records := make([]InspectionRecord, len(files))
	for index, file := range files {
		bound := supplied[index]
		if bound.Ordinal != index || !idPattern.MatchString(bound.ID) || !ValidProtocol(bound.Protocol) ||
			bound.Identifier != RuntimeIdentifier(bound.ID) ||
			(bound.Disposition != "new" && bound.Disposition != "already_imported") || len(bound.Issues) != 0 {
			return nil, ErrInvalidReceipt
		}
		if err := ValidateOriginalFilename(file.Name); err != nil {
			return nil, ErrInvalidReceipt
		}
		protocol, protocolIssue := detectProtocol(file)
		if protocolIssue != nil || protocol != bound.Protocol {
			return nil, ErrInvalidReceipt
		}
		policy, err := ValidateImportedProfile(protocol, file.Bytes)
		if err != nil {
			return nil, ErrInvalidReceipt
		}
		if protocol == ProtocolWireGuard {
			if err := s.checker.CheckWireGuard(file.Bytes); err != nil {
				return nil, ErrInvalidReceipt
			}
		}
		digest := sha256.Sum256(file.Bytes)
		record := bound
		record.digest = hex.EncodeToString(digest[:])
		record.wireGuardPublicKeyDigest = policy.WireGuardPublicKeySHA256
		record.protocolOverride = file.ProtocolOverride
		record.Issues = []PolicyIssue{}
		records[index] = record
	}
	return records, nil
}

func (s *ImportService) generateIdentity(protocol string, used map[string]struct{}) (string, string, error) {
	for attempts := 0; attempts < 128; attempts++ {
		id, err := GenerateID(s.random)
		if err != nil {
			return "", "", err
		}
		identifier := RuntimeIdentifier(id)
		if _, exists := used[identifier]; exists {
			continue
		}
		if protocol == ProtocolWireGuard && s.runtimeNameAvailable != nil {
			available, err := s.runtimeNameAvailable(identifier)
			if err != nil {
				return "", "", err
			}
			if !available {
				continue
			}
		}
		return id, identifier, nil
	}
	return "", "", errors.New("could not allocate a unique profile identity")
}

func (s *ImportService) acquire() bool {
	select {
	case <-s.gate:
		return true
	default:
		return false
	}
}

func (s *ImportService) release() { s.gate <- struct{}{} }

func (s *ImportService) sign(revision uint64, expiry time.Time, records []InspectionRecord) string {
	mac := s.receiptMAC(revision, expiry, records)
	envelope := make([]byte, 1+8+len(mac))
	envelope[0] = receiptVersion
	binary.BigEndian.PutUint64(envelope[1:9], uint64(expiry.Unix()))
	copy(envelope[9:], mac)
	return base64.RawURLEncoding.EncodeToString(envelope)
}

func (s *ImportService) receiptMAC(revision uint64, expiry time.Time, records []InspectionRecord) []byte {
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write(canonicalReceiptInput(revision, expiry.Unix(), records))
	return mac.Sum(nil)
}

func decodeReceipt(receipt string) (time.Time, []byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(receipt)
	if err != nil || len(data) != 41 || data[0] != receiptVersion {
		return time.Time{}, nil, ErrInvalidReceipt
	}
	if base64.RawURLEncoding.EncodeToString(data) != receipt {
		return time.Time{}, nil, ErrInvalidReceipt
	}
	seconds := binary.BigEndian.Uint64(data[1:9])
	if seconds > uint64(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix()) {
		return time.Time{}, nil, ErrInvalidReceipt
	}
	return time.Unix(int64(seconds), 0).UTC(), data[9:], nil
}

func canonicalReceiptInput(revision uint64, expiry int64, records []InspectionRecord) []byte {
	var buffer bytes.Buffer
	writeUint64(&buffer, uint64(ImportPolicyVersion))
	writeUint64(&buffer, revision)
	writeUint64(&buffer, uint64(expiry))
	writeUint64(&buffer, uint64(len(records)))
	for _, record := range records {
		writeUint64(&buffer, uint64(record.Ordinal))
		for _, value := range []string{record.digest, record.ID, record.Protocol, record.Identifier, record.Disposition, record.wireGuardPublicKeyDigest, record.protocolOverride} {
			writeString(&buffer, value)
		}
	}
	return buffer.Bytes()
}

func writeString(writer io.Writer, value string) {
	writeUint64(writer, uint64(len(value)))
	_, _ = io.WriteString(writer, value)
}

func writeUint64(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func exactReplay(manifest Manifest, records []InspectionRecord) ([]ImportResult, bool) {
	result := make([]ImportResult, len(records))
	for index, record := range records {
		profile, found := manifest.Profile(record.ID)
		if !found || !recordMatchesProfile(record, profile) {
			return nil, false
		}
		result[index] = ImportResult{Ordinal: index, Result: "already_imported", Profile: profile}
	}
	return result, true
}

func recordMatchesProfile(record InspectionRecord, profile Profile) bool {
	return record.ID == profile.ID && record.Protocol == profile.Protocol && record.Identifier == profile.Identifier &&
		record.digest == profile.ContentSHA256 && record.wireGuardPublicKeyDigest == profile.WireGuardPublicKeySHA256
}

func validateImportEnvelope(files []ImportFile) error {
	if len(files) == 0 {
		return errors.New("at least one profile file is required")
	}
	if len(files) > MaxImportFiles {
		return ErrCapacity
	}
	total := 0
	for _, file := range files {
		if len(file.Bytes) == 0 || len(file.Bytes) > MaxProfileBytes {
			return errors.New("profile file is outside its size limit")
		}
		total += len(file.Bytes)
		if total > MaxImportRequest {
			return errors.New("import request exceeds 32 MiB")
		}
		if file.ProtocolOverride != "" && !ValidProtocol(file.ProtocolOverride) {
			return errors.New("invalid protocol override")
		}
	}
	return nil
}

func detectProtocol(file ImportFile) (string, *PolicyIssue) {
	extension := strings.ToLower(filepath.Ext(file.Name))
	if extension == ".ovpn" {
		if file.ProtocolOverride != "" && file.ProtocolOverride != ProtocolOpenVPN {
			value := issue("protocol", "protocol_mismatch", ".ovpn files are inspected as OpenVPN profiles.")
			return "", &value
		}
		return ProtocolOpenVPN, nil
	}
	if extension != ".conf" {
		value := issue("file", "unsupported_extension", "Choose a self-contained .ovpn or .conf profile.")
		return "", &value
	}
	if file.ProtocolOverride != "" {
		return file.ProtocolOverride, nil
	}
	_, wireGuardErr := ValidateWireGuardImport(file.Bytes)
	openVPNErr := ValidateOpenVPNImport(file.Bytes)
	if wireGuardErr == nil && openVPNErr != nil {
		return ProtocolWireGuard, nil
	}
	if openVPNErr == nil && wireGuardErr != nil {
		return ProtocolOpenVPN, nil
	}
	text := strings.ToLower(string(file.Bytes))
	wireGuardSignal := strings.Contains(text, "[interface]") || strings.Contains(text, "privatekey")
	openVPNSignal := strings.Contains(text, "client") || strings.Contains(text, "remote ") || strings.Contains(text, "<ca>")
	if wireGuardSignal != openVPNSignal {
		if wireGuardSignal {
			return ProtocolWireGuard, nil
		}
		return ProtocolOpenVPN, nil
	}
	value := issue("protocol", "protocol_ambiguous", "Choose OpenVPN or WireGuard, then inspect the file again.")
	return "", &value
}

func policyIssue(err error) PolicyIssue {
	var policyErr *PolicyError
	if errors.As(err, &policyErr) {
		return issue("file", policyErr.Code, policyErr.Message)
	}
	return issue("file", "policy_rejected", "The profile is outside the supported import policy.")
}

func issue(field, code, message string) PolicyIssue {
	return PolicyIssue{Field: field, Code: code, Message: message}
}

func suggestedDisplayName(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	base = strings.TrimSpace(strings.Map(func(char rune) rune {
		if char == '_' || char == '-' {
			return ' '
		}
		if unicode.IsControl(char) {
			return -1
		}
		return char
	}, base))
	if base == "" {
		return "Imported profile"
	}
	words := strings.Fields(base)
	for index, word := range words {
		first, size := utf8.DecodeRuneInString(word)
		words[index] = strings.ToUpper(string(first)) + word[size:]
	}
	result := strings.Join(words, " ")
	for utf8.RuneCountInString(result) > MaxDisplayNameRunes || len(result) > MaxDisplayNameBytes {
		_, size := utf8.DecodeLastRuneInString(result)
		result = result[:len(result)-size]
	}
	return strings.TrimSpace(result)
}

func DecodeMetadataDocument(data []byte) (map[int]Metadata, error) {
	var raw map[string]struct {
		DisplayName string `json:"display_name"`
		Group       string `json:"group"`
		Location    string `json:"location"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("metadata must contain exactly one JSON value")
	}
	result := make(map[int]Metadata, len(raw))
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ordinal, err := strconv.Atoi(key)
		if err != nil || ordinal < 0 || strconv.Itoa(ordinal) != key {
			return nil, errors.New("metadata keys must be canonical file ordinals")
		}
		value := raw[key]
		result[ordinal] = Metadata{DisplayName: value.DisplayName, Group: value.Group, Location: value.Location}
	}
	return result, nil
}
