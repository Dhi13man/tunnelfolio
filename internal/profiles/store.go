package profiles

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/securefs"
	"golang.org/x/sys/unix"
)

const manifestName = "manifest.json"

type StoreOptions struct {
	Root        string
	RequiredUID int
	ReadOnly    bool
	Now         func() time.Time
	Random      io.Reader
	Checkpoint  func(string) error
}

type Store struct {
	root        string
	libraryRoot string
	manifest    Manifest
	requiredUID int
	readOnly    bool
	now         func() time.Time
	random      io.Reader
	checkpoint  func(string) error
	lock        *securefs.Lock

	mu                sync.RWMutex
	durabilityUnknown bool
}

type NewObject struct {
	Profile Profile
	Bytes   []byte
}

type PublicationResult struct {
	Manifest       Manifest
	CleanupPending bool
}

type RemovalResult struct {
	Profile        Profile
	CleanupPending bool
	CleanupError   error
}

func OpenStore(options StoreOptions) (*Store, error) {
	if options.Root == "" {
		return nil, errors.New("profile store root is required")
	}
	if options.RequiredUID < 0 {
		return nil, errors.New("required store owner is invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if err := securefs.EnsurePrivateDir(options.Root, options.RequiredUID); err != nil {
		return nil, fmt.Errorf("prepare profile store: %w", err)
	}
	for _, path := range []string{
		filepath.Join(options.Root, "library"),
		filepath.Join(options.Root, "library", ProtocolOpenVPN),
		filepath.Join(options.Root, "library", ProtocolWireGuard),
		filepath.Join(options.Root, "library", ".transactions"),
		filepath.Join(options.Root, "library", ".garbage"),
		filepath.Join(options.Root, "library", ".executions"),
	} {
		if err := securefs.EnsurePrivateDir(path, options.RequiredUID); err != nil {
			return nil, fmt.Errorf("prepare managed library: %w", err)
		}
	}
	lock, err := securefs.AcquireLock(options.Root, options.RequiredUID)
	if err != nil {
		return nil, err
	}
	store := &Store{
		root:        filepath.Clean(options.Root),
		libraryRoot: filepath.Join(filepath.Clean(options.Root), "library"),
		requiredUID: options.RequiredUID,
		readOnly:    options.ReadOnly,
		now:         options.Now,
		random:      options.Random,
		checkpoint:  options.Checkpoint,
		lock:        lock,
	}
	manifestPath := filepath.Join(store.root, manifestName)
	if err := securefs.ReadJSON(manifestPath, &store.manifest, securefs.DefaultJSONLimit, store.requiredUID); err != nil {
		if !errors.Is(err, securefs.ErrNotExist) {
			_ = lock.Close()
			return nil, fmt.Errorf("load profile manifest: %w", err)
		}
		store.manifest = InitialManifest()
		if !store.readOnly {
			result, writeErr := securefs.WriteJSONAtomic(manifestPath, store.manifest, store.requiredUID, nil)
			if writeErr != nil || !result.Durable {
				_ = lock.Close()
				return nil, fmt.Errorf("create profile manifest: %w", writeErr)
			}
		}
	} else {
		if err := ValidateManifest(store.manifest); err != nil {
			_ = lock.Close()
			return nil, err
		}
		if err := securefs.SyncPrivateFile(manifestPath, store.requiredUID); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("sync loaded profile manifest: %w", err)
		}
		root, openErr := securefs.OpenPrivateDir(store.root, store.requiredUID)
		if openErr != nil {
			_ = lock.Close()
			return nil, openErr
		}
		syncErr := securefs.Sync(root)
		_ = root.Close()
		if syncErr != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("sync profile store: %w", syncErr)
		}
	}
	if !store.readOnly {
		if err := store.cleanupRemnants(store.manifest); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("clean managed library remnants: %w", err)
		}
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.lock.Close()
}

func (s *Store) Snapshot() Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manifest.Clone()
}

func (s *Store) List() []Profile {
	return SortedProfiles(s.Snapshot().Profiles)
}

func (s *Store) Resolve(id string) (Profile, error) {
	s.mu.RLock()
	profile, exists := s.manifest.Profile(id)
	s.mu.RUnlock()
	if !exists {
		return Profile{}, ErrNotFound
	}
	if err := s.validateObject(profile); err != nil {
		return Profile{}, fmt.Errorf("validate profile object: %w", err)
	}
	return profile, nil
}

func (s *Store) PrepareExecution(id string) (Profile, string, func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return Profile{}, "", nil, ErrReadOnly
	}
	profile, exists := s.manifest.Profile(id)
	if !exists {
		return Profile{}, "", nil, ErrNotFound
	}
	data, err := s.readValidatedObject(profile)
	if err != nil {
		return Profile{}, "", nil, fmt.Errorf("validate profile object: %w", err)
	}
	executionName, err := s.randomName("exec-")
	if err != nil {
		return Profile{}, "", nil, err
	}
	executionsPath := filepath.Join(s.libraryRoot, ".executions")
	executions, err := securefs.OpenPrivateDir(executionsPath, s.requiredUID)
	if err != nil {
		return Profile{}, "", nil, err
	}
	execution, err := securefs.MkdirExclusive(executions, executionName, s.requiredUID)
	if err != nil {
		_ = executions.Close()
		return Profile{}, "", nil, err
	}
	removeIncomplete := func() {
		_ = execution.Close()
		_ = securefs.RemoveTreeAt(executions, executionName, s.requiredUID)
		_ = executions.Close()
	}
	filename := objectFilename(profile)
	if err := securefs.WriteExclusive(execution, filename, data, s.requiredUID); err != nil {
		removeIncomplete()
		return Profile{}, "", nil, err
	}
	if err := securefs.Sync(execution); err != nil {
		removeIncomplete()
		return Profile{}, "", nil, err
	}
	if err := execution.Close(); err != nil {
		_ = securefs.RemoveTreeAt(executions, executionName, s.requiredUID)
		_ = executions.Close()
		return Profile{}, "", nil, err
	}
	if err := securefs.Sync(executions); err != nil {
		_ = securefs.RemoveTreeAt(executions, executionName, s.requiredUID)
		_ = executions.Close()
		return Profile{}, "", nil, err
	}
	if err := executions.Close(); err != nil {
		return Profile{}, "", nil, err
	}
	var cleanupMu sync.Mutex
	cleaned := false
	cleanup := func() error {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		if cleaned {
			return nil
		}
		root, openErr := securefs.OpenPrivateDir(executionsPath, s.requiredUID)
		if openErr != nil {
			return openErr
		}
		cleanupErr := securefs.RemoveTreeAt(root, executionName, s.requiredUID)
		if securefs.IsNotExist(cleanupErr) {
			cleanupErr = nil
		}
		if cleanupErr == nil {
			cleanupErr = securefs.Sync(root)
		}
		cleanupErr = errors.Join(cleanupErr, root.Close())
		if cleanupErr == nil {
			cleaned = true
		}
		return cleanupErr
	}
	return profile, filepath.Join(executionsPath, executionName, filename), cleanup, nil
}

func (s *Store) ObjectPath(profile Profile) string {
	name := "profile.ovpn"
	if profile.Protocol == ProtocolWireGuard {
		name = profile.Identifier + ".conf"
	}
	return filepath.Join(s.libraryRoot, profile.Protocol, profile.ID, name)
}

func (s *Store) SetPreferences(favorites, recents []string, startupMode string) (Manifest, error) {
	return s.mutate(func(manifest *Manifest) error {
		manifest.Favorites = append([]string{}, favorites...)
		manifest.Recents = append([]string{}, recents...)
		manifest.StartupMode = startupMode
		return nil
	})
}

func (s *Store) SetConnection(desiredProfile string, connectedAt int64, addRecent bool) (Manifest, error) {
	return s.mutate(func(manifest *Manifest) error {
		manifest.DesiredProfile = desiredProfile
		manifest.ConnectedAt = connectedAt
		if addRecent && desiredProfile != "" {
			manifest.Recents = prependUnique(manifest.Recents, desiredProfile, MaxRecents)
		}
		return nil
	})
}

func (s *Store) UpdateMetadata(id string, patch MetadataPatch) (Profile, error) {
	if patch.DisplayName == nil && patch.Group == nil && patch.Location == nil && !patch.ClearLocation {
		return Profile{}, errors.New("metadata patch is empty")
	}
	var updated Profile
	_, err := s.mutate(func(manifest *Manifest) error {
		for index := range manifest.Profiles {
			if manifest.Profiles[index].ID != id {
				continue
			}
			if patch.DisplayName != nil {
				manifest.Profiles[index].DisplayName = *patch.DisplayName
			}
			if patch.Group != nil {
				manifest.Profiles[index].Group = *patch.Group
			}
			if patch.ClearLocation {
				manifest.Profiles[index].Location = ""
			} else if patch.Location != nil {
				manifest.Profiles[index].Location = *patch.Location
			}
			updated = manifest.Profiles[index]
			return ValidateMetadata(Metadata{DisplayName: updated.DisplayName, Group: updated.Group, Location: updated.Location})
		}
		return ErrNotFound
	})
	if err != nil {
		return Profile{}, err
	}
	return updated, nil
}

func (s *Store) Remove(id string) (RemovalResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prepareMutationLocked(); err != nil {
		return RemovalResult{}, err
	}
	removed, exists := s.manifest.Profile(id)
	if !exists {
		return RemovalResult{}, ErrNotFound
	}
	candidate := s.manifest.Clone()
	candidate.Profiles = removeProfile(candidate.Profiles, id)
	candidate.Favorites = removeID(candidate.Favorites, id)
	candidate.Recents = removeID(candidate.Recents, id)
	if candidate.DesiredProfile == id {
		candidate.DesiredProfile = ""
		candidate.ConnectedAt = 0
	}
	candidate.LibraryRevision++
	if err := ValidateManifest(candidate); err != nil {
		return RemovalResult{}, err
	}
	if err := s.publishManifestLocked(candidate); err != nil {
		return RemovalResult{}, err
	}
	result := RemovalResult{Profile: removed}
	if err := s.garbageCollectObjectLocked(removed); err != nil {
		result.CleanupPending = true
		result.CleanupError = err
	}
	return result, nil
}

func (s *Store) Publish(expectedRevision uint64, objects []NewObject) (PublicationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prepareMutationLocked(); err != nil {
		return PublicationResult{}, err
	}
	if s.manifest.LibraryRevision != expectedRevision {
		return PublicationResult{}, ErrStaleInspection
	}
	if len(objects) == 0 {
		return PublicationResult{Manifest: s.manifest.Clone()}, nil
	}
	if len(s.manifest.Profiles)+len(objects) > MaxProfiles {
		return PublicationResult{}, ErrCapacity
	}
	candidate := s.manifest.Clone()
	seenIDs := make(map[string]struct{}, len(candidate.Profiles)+len(objects))
	seenContents := make(map[string]struct{}, len(candidate.Profiles)+len(objects))
	for _, profile := range candidate.Profiles {
		seenIDs[profile.ID] = struct{}{}
		seenContents[profile.ContentSHA256] = struct{}{}
	}
	for _, object := range objects {
		if len(object.Bytes) == 0 || len(object.Bytes) > MaxProfileBytes {
			return PublicationResult{}, errors.New("profile object is outside its size limit")
		}
		if err := ValidateProfile(object.Profile); err != nil {
			return PublicationResult{}, err
		}
		digest := sha256.Sum256(object.Bytes)
		if hex.EncodeToString(digest[:]) != object.Profile.ContentSHA256 {
			return PublicationResult{}, errors.New("profile object fingerprint does not match")
		}
		policy, err := ValidateImportedProfile(object.Profile.Protocol, object.Bytes)
		if err != nil {
			return PublicationResult{}, err
		}
		if policy.WireGuardPublicKeySHA256 != object.Profile.WireGuardPublicKeySHA256 {
			return PublicationResult{}, errors.New("profile object identity does not match")
		}
		if _, exists := seenIDs[object.Profile.ID]; exists {
			return PublicationResult{}, ErrConflict
		}
		if _, exists := seenContents[object.Profile.ContentSHA256]; exists {
			return PublicationResult{}, ErrConflict
		}
		seenIDs[object.Profile.ID] = struct{}{}
		seenContents[object.Profile.ContentSHA256] = struct{}{}
		candidate.Profiles = append(candidate.Profiles, object.Profile)
	}
	candidate.LibraryRevision++
	if err := ValidateManifest(candidate); err != nil {
		return PublicationResult{}, err
	}
	transactionName, err := s.randomName("txn-")
	if err != nil {
		return PublicationResult{}, err
	}
	if err := s.check("before_transactions_open"); err != nil {
		return PublicationResult{}, err
	}
	transactions, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, ".transactions"), s.requiredUID)
	if err != nil {
		return PublicationResult{}, err
	}
	if err := s.check("after_transactions_open"); err != nil {
		return PublicationResult{}, errors.Join(err, transactions.Close())
	}
	transactionsOpen := true
	defer func() {
		if transactionsOpen {
			_ = transactions.Close()
		}
	}()
	if err := s.check("before_transaction_create"); err != nil {
		return PublicationResult{}, err
	}
	transactionDir, err := securefs.MkdirExclusive(transactions, transactionName, s.requiredUID)
	if err != nil {
		return PublicationResult{}, err
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			_ = transactionDir.Close()
		}
	}()
	if err := s.check("after_transaction_create"); err != nil {
		return PublicationResult{}, err
	}
	for _, object := range objects {
		if err := s.check("before_object_stage"); err != nil {
			return PublicationResult{}, err
		}
		if err := s.check("before_object_create"); err != nil {
			return PublicationResult{}, err
		}
		objectDir, err := securefs.MkdirExclusive(transactionDir, object.Profile.ID, s.requiredUID)
		if err != nil {
			return PublicationResult{}, err
		}
		if err := s.check("after_object_create"); err != nil {
			return PublicationResult{}, errors.Join(err, objectDir.Close())
		}
		name := objectFilename(object.Profile)
		writeErr := s.check("before_object_write")
		if writeErr == nil {
			writeErr = securefs.WriteExclusive(objectDir, name, object.Bytes, s.requiredUID)
		}
		if writeErr == nil {
			writeErr = s.check("after_object_write")
		}
		if writeErr == nil {
			writeErr = s.check("before_object_sync")
		}
		if writeErr == nil {
			writeErr = securefs.Sync(objectDir)
		}
		if writeErr == nil {
			writeErr = s.check("after_object_sync")
		}
		closeErr := s.closeBoundary("object", objectDir)
		if writeErr != nil || closeErr != nil {
			return PublicationResult{}, errors.Join(writeErr, closeErr)
		}
	}
	if err := s.check("before_transaction_sync"); err != nil {
		return PublicationResult{}, err
	}
	if err := securefs.Sync(transactionDir); err != nil {
		return PublicationResult{}, err
	}
	if err := s.check("after_transaction_sync"); err != nil {
		return PublicationResult{}, err
	}
	for _, object := range objects {
		if err := s.check("before_destination_open"); err != nil {
			return PublicationResult{}, err
		}
		destination, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, object.Profile.Protocol), s.requiredUID)
		if err != nil {
			return PublicationResult{}, err
		}
		if err := s.check("after_destination_open"); err != nil {
			return PublicationResult{}, errors.Join(err, destination.Close())
		}
		renameErr := s.check("before_object_publish")
		if renameErr == nil {
			renameErr = securefs.RenameNoReplace(transactionDir, object.Profile.ID, destination, object.Profile.ID)
		}
		if errors.Is(renameErr, unix.EEXIST) {
			renameErr = s.validateObject(object.Profile)
		}
		if renameErr == nil {
			renameErr = s.check("after_object_publish")
		}
		if renameErr == nil {
			renameErr = s.check("before_object_parent_sync")
		}
		if renameErr == nil {
			renameErr = securefs.Sync(destination)
		}
		if renameErr == nil {
			renameErr = s.check("after_object_parent_sync")
		}
		closeErr := s.closeBoundary("destination", destination)
		if renameErr != nil || closeErr != nil {
			return PublicationResult{}, errors.Join(renameErr, closeErr)
		}
	}
	if err := s.publishManifestLocked(candidate); err != nil {
		if errors.Is(err, ErrOutcomeAmbiguous) {
			return PublicationResult{Manifest: s.manifest.Clone(), CleanupPending: true}, err
		}
		return PublicationResult{}, err
	}
	if err := s.closeBoundary("transaction", transactionDir); err != nil {
		transactionOpen = false
		return PublicationResult{Manifest: s.manifest.Clone(), CleanupPending: true}, nil
	}
	transactionOpen = false
	cleanupErr := s.check("before_transaction_remove")
	if cleanupErr == nil {
		cleanupErr = securefs.RemoveTreeAt(transactions, transactionName, s.requiredUID)
	}
	if cleanupErr == nil {
		cleanupErr = s.check("after_transaction_remove")
	}
	if cleanupErr == nil {
		cleanupErr = s.check("before_transactions_sync")
	}
	if cleanupErr == nil {
		cleanupErr = securefs.Sync(transactions)
	}
	if cleanupErr == nil {
		cleanupErr = s.check("after_transactions_sync")
	}
	if cleanupErr == nil {
		cleanupErr = s.closeBoundary("transactions", transactions)
		transactionsOpen = false
	}
	if cleanupErr != nil && transactionsOpen {
		cleanupErr = errors.Join(cleanupErr, transactions.Close())
		transactionsOpen = false
	}
	return PublicationResult{Manifest: s.manifest.Clone(), CleanupPending: cleanupErr != nil}, nil
}

func (s *Store) RepairDurability() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repairDurabilityLocked()
}

func (s *Store) mutate(change func(*Manifest) error) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prepareMutationLocked(); err != nil {
		return Manifest{}, err
	}
	candidate := s.manifest.Clone()
	if err := change(&candidate); err != nil {
		return Manifest{}, err
	}
	candidate.LibraryRevision++
	if err := ValidateManifest(candidate); err != nil {
		return Manifest{}, err
	}
	if err := s.publishManifestLocked(candidate); err != nil {
		return Manifest{}, err
	}
	return s.manifest.Clone(), nil
}

func (s *Store) prepareMutationLocked() error {
	if s.readOnly {
		return ErrReadOnly
	}
	return s.repairDurabilityLocked()
}

func (s *Store) publishManifestLocked(candidate Manifest) error {
	checkpoint := func(name string) error { return s.check("manifest_" + name) }
	result, err := securefs.WriteJSONAtomic(filepath.Join(s.root, manifestName), candidate, s.requiredUID, checkpoint)
	if err != nil {
		if result.Published {
			s.manifest = candidate
			s.durabilityUnknown = true
			return errors.Join(ErrOutcomeAmbiguous, err)
		}
		return err
	}
	if !result.Durable {
		s.manifest = candidate
		s.durabilityUnknown = true
		return ErrOutcomeAmbiguous
	}
	s.manifest = candidate
	s.durabilityUnknown = false
	return nil
}

func (s *Store) repairDurabilityLocked() error {
	if !s.durabilityUnknown {
		return nil
	}
	var manifest Manifest
	manifestPath := filepath.Join(s.root, manifestName)
	if err := securefs.ReadJSON(manifestPath, &manifest, securefs.DefaultJSONLimit, s.requiredUID); err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	if err := ValidateManifest(manifest); err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	if err := s.validateReferencedObjects(manifest); err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	if err := securefs.SyncPrivateFile(manifestPath, s.requiredUID); err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	root, err := securefs.OpenPrivateDir(s.root, s.requiredUID)
	if err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	err = securefs.Sync(root)
	_ = root.Close()
	if err != nil {
		return errors.Join(ErrOutcomeAmbiguous, err)
	}
	s.manifest = manifest
	s.durabilityUnknown = false
	return nil
}

func (s *Store) validateReferencedObjects(manifest Manifest) error {
	for _, profile := range manifest.Profiles {
		if err := s.validateObject(profile); err != nil {
			return fmt.Errorf("profile %s: %w", profile.ID, err)
		}
	}
	return nil
}

func (s *Store) validateObject(profile Profile) error {
	_, err := s.readValidatedObject(profile)
	return err
}

func (s *Store) readValidatedObject(profile Profile) ([]byte, error) {
	objectDir, err := securefs.OpenPrivateDir(filepath.Dir(s.ObjectPath(profile)), s.requiredUID)
	if err != nil {
		return nil, err
	}
	defer objectDir.Close()
	entries, err := objectDir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 || entries[0].Name() != objectFilename(profile) {
		return nil, errors.New("profile object directory has unexpected contents")
	}
	data, err := securefs.ReadFileAt(objectDir, objectFilename(profile), MaxProfileBytes, s.requiredUID)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != profile.ContentSHA256 {
		return nil, errors.New("profile content fingerprint does not match")
	}
	policy, err := ValidateImportedProfile(profile.Protocol, data)
	if err != nil {
		return nil, fmt.Errorf("profile no longer passes import policy: %w", err)
	}
	if policy.WireGuardPublicKeySHA256 != profile.WireGuardPublicKeySHA256 {
		return nil, errors.New("profile runtime identity does not match")
	}
	return data, nil
}

func (s *Store) cleanupRemnants(manifest Manifest) error {
	for _, special := range []string{".transactions", ".garbage", ".executions"} {
		directory, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, special), s.requiredUID)
		if err != nil {
			return err
		}
		entries, err := directory.ReadDir(-1)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					err = errors.New("managed library remnant is not a directory")
					break
				}
				if removeErr := securefs.RemoveTreeAt(directory, entry.Name(), s.requiredUID); removeErr != nil {
					err = removeErr
					break
				}
			}
		}
		if err == nil {
			err = securefs.Sync(directory)
		}
		_ = directory.Close()
		if err != nil {
			return err
		}
	}
	referenced := make(map[string]struct{}, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		referenced[profile.Protocol+"/"+profile.ID] = struct{}{}
	}
	for _, protocol := range []string{ProtocolOpenVPN, ProtocolWireGuard} {
		directory, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, protocol), s.requiredUID)
		if err != nil {
			return err
		}
		entries, err := directory.ReadDir(-1)
		_ = directory.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if _, ok := referenced[protocol+"/"+entry.Name()]; ok {
				continue
			}
			if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
				return errors.New("unreferenced library object is structurally invalid")
			}
			if err := s.quarantineUnreferenced(protocol, entry.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) quarantineUnreferenced(protocol, id string) error {
	protocolDir, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, protocol), s.requiredUID)
	if err != nil {
		return err
	}
	defer protocolDir.Close()
	objectDir, err := securefs.OpenDirAt(protocolDir, id, s.requiredUID)
	if err != nil {
		return err
	}
	entries, err := objectDir.ReadDir(-1)
	if err != nil {
		_ = objectDir.Close()
		return err
	}
	if len(entries) != 1 || !entries[0].Type().IsRegular() {
		_ = objectDir.Close()
		return errors.New("unreferenced library object has unexpected contents")
	}
	name := entries[0].Name()
	if protocol == ProtocolOpenVPN && name != "profile.ovpn" || protocol == ProtocolWireGuard && (!strings.HasSuffix(name, ".conf") || !identifierPattern.MatchString(strings.TrimSuffix(name, ".conf"))) {
		_ = objectDir.Close()
		return errors.New("unreferenced library object has invalid runtime identity")
	}
	data, err := securefs.ReadFileAt(objectDir, name, MaxProfileBytes, s.requiredUID)
	_ = objectDir.Close()
	if err != nil {
		return err
	}
	if _, err := ValidateImportedProfile(protocol, data); err != nil {
		return errors.New("unreferenced library object does not pass import policy")
	}
	garbage, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, ".garbage"), s.requiredUID)
	if err != nil {
		return err
	}
	defer garbage.Close()
	garbageName := fmt.Sprintf("%s-%s", protocol, id)
	if err := securefs.RenameNoReplace(protocolDir, id, garbage, garbageName); err != nil {
		return err
	}
	if err := errors.Join(securefs.Sync(protocolDir), securefs.Sync(garbage)); err != nil {
		return err
	}
	if err := securefs.RemoveTreeAt(garbage, garbageName, s.requiredUID); err != nil {
		return err
	}
	return securefs.Sync(garbage)
}

func (s *Store) garbageCollectObjectLocked(profile Profile) error {
	protocolDir, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, profile.Protocol), s.requiredUID)
	if err != nil {
		return err
	}
	defer protocolDir.Close()
	garbage, err := securefs.OpenPrivateDir(filepath.Join(s.libraryRoot, ".garbage"), s.requiredUID)
	if err != nil {
		return err
	}
	defer garbage.Close()
	garbageName := fmt.Sprintf("removed-%d-%s", s.manifest.LibraryRevision, profile.ID)
	if err := s.check("removal_before_quarantine"); err != nil {
		return err
	}
	if err := securefs.RenameNoReplace(protocolDir, profile.ID, garbage, garbageName); err != nil {
		return err
	}
	if err := s.check("removal_after_quarantine"); err != nil {
		return err
	}
	if err := errors.Join(securefs.Sync(protocolDir), securefs.Sync(garbage)); err != nil {
		return err
	}
	if err := s.check("removal_after_parent_sync"); err != nil {
		return err
	}
	if err := securefs.RemoveTreeAt(garbage, garbageName, s.requiredUID); err != nil {
		return err
	}
	if err := s.check("removal_after_cleanup"); err != nil {
		return err
	}
	if err := securefs.Sync(garbage); err != nil {
		return err
	}
	return s.check("removal_after_garbage_sync")
}

func (s *Store) randomName(prefix string) (string, error) {
	id, err := GenerateID(s.random)
	if err != nil {
		return "", err
	}
	return prefix + strings.TrimPrefix(id, "tf_"), nil
}

func (s *Store) check(name string) error {
	if s.checkpoint == nil {
		return nil
	}
	return s.checkpoint(name)
}

func (s *Store) closeBoundary(name string, closer io.Closer) error {
	beforeErr := s.check("before_" + name + "_close")
	closeErr := closer.Close()
	if beforeErr != nil || closeErr != nil {
		return errors.Join(beforeErr, closeErr)
	}
	return s.check("after_" + name + "_close")
}

func objectFilename(profile Profile) string {
	if profile.Protocol == ProtocolWireGuard {
		return profile.Identifier + ".conf"
	}
	return "profile.ovpn"
}

func prependUnique(values []string, value string, limit int) []string {
	result := []string{value}
	for _, candidate := range values {
		if candidate != value {
			result = append(result, candidate)
		}
		if len(result) == limit {
			break
		}
	}
	return result
}

func removeProfile(values []Profile, id string) []Profile {
	result := make([]Profile, 0, len(values)-1)
	for _, profile := range values {
		if profile.ID != id {
			result = append(result, profile)
		}
	}
	return result
}

func removeID(values []string, id string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != id {
			result = append(result, value)
		}
	}
	return result
}

func (s *Store) IDsByProtocol(protocol string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	for _, profile := range s.manifest.Profiles {
		if profile.Protocol == protocol {
			result = append(result, profile.ID)
		}
	}
	sort.Strings(result)
	return result
}
