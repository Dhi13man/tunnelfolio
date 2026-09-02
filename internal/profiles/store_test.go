package profiles

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dhi13man/tunnelfolio/internal/securefs"
)

func TestStorePublishesByteExactObjectAndReloads(t *testing.T) {
	root := t.TempDir()
	store := openTestStore(t, StoreOptions{Root: root, RequiredUID: -1})
	data := validWireGuardProfile(7)
	profile := testProfile(t, ProtocolWireGuard, data, 7)
	result, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.LibraryRevision != 1 || len(result.Manifest.Profiles) != 1 {
		t.Fatalf("unexpected manifest: %+v", result.Manifest)
	}
	stored, err := os.ReadFile(store.ObjectPath(profile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, data) {
		t.Fatal("stored profile bytes changed")
	}
	info, err := os.Stat(store.ObjectPath(profile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode is %o", info.Mode().Perm())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	resolved, err := reloaded.Resolve(profile.ID)
	if err != nil || resolved != profile {
		t.Fatalf("reloaded profile = %+v, %v", resolved, err)
	}
}

func TestStoreReopensWithCorruptReferencedObjectUnavailable(t *testing.T) {
	root := t.TempDir()
	store := openTestStore(t, StoreOptions{Root: root, RequiredUID: -1})
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 30)
	if _, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPreferences(nil, nil, StartupRestore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(profile.ID, fixedTestTime.Unix(), false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "library", ProtocolOpenVPN, profile.ID, "profile.ovpn"), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatalf("OpenStore() rejected trusted manifest: %v", err)
	}
	defer reloaded.Close()
	manifest := reloaded.Snapshot()
	if manifest.DesiredProfile != profile.ID || len(manifest.Profiles) != 1 || manifest.Profiles[0].ID != profile.ID {
		t.Fatalf("manifest changed after object corruption: %+v", manifest)
	}
	if _, err := reloaded.Resolve(profile.ID); err == nil {
		t.Fatal("Resolve() accepted corrupt object")
	}
	if _, _, _, err := reloaded.PrepareExecution(profile.ID); err == nil {
		t.Fatal("PrepareExecution() accepted corrupt object")
	}
	assertDirectoryEmpty(t, filepath.Join(root, "library", ".executions"))
}

func TestStoreLifetimeLockExcludesSecondProcess(t *testing.T) {
	root := t.TempDir()
	store := openTestStore(t, StoreOptions{Root: root, RequiredUID: -1})
	second, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if second != nil {
		_ = second.Close()
	}
	if !errors.Is(err, securefs.ErrLocked) {
		t.Fatalf("second store returned %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	_ = third.Close()
}

func TestStoreFaultBeforeManifestLeavesNoVisibleProfile(t *testing.T) {
	root := t.TempDir()
	fail := true
	store := openTestStore(t, StoreOptions{
		Root: root, RequiredUID: -1,
		Checkpoint: func(name string) error {
			if fail && name == "after_object_parent_sync" {
				return errors.New("injected crash")
			}
			return nil
		},
	})
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 3)
	if _, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}}); err == nil {
		t.Fatal("publication unexpectedly succeeded")
	}
	if len(store.List()) != 0 {
		t.Fatal("failed publication became manifest-visible")
	}
	fail = false
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if len(reloaded.List()) != 0 {
		t.Fatal("orphan became visible after restart")
	}
	entries, err := os.ReadDir(filepath.Join(root, "library", ProtocolOpenVPN))
	if err != nil || len(entries) != 0 {
		t.Fatalf("orphan cleanup = %v, entries=%d", err, len(entries))
	}
}

func TestStorePublicationFaultMatrixConvergesAfterReopen(t *testing.T) {
	for _, checkpoint := range []string{
		"before_transactions_open",
		"after_transactions_open",
		"before_transaction_create",
		"after_transaction_create",
		"before_object_stage",
		"before_object_create",
		"after_object_create",
		"before_object_write",
		"after_object_write",
		"before_object_sync",
		"after_object_sync",
		"before_object_close",
		"after_object_close",
		"before_transaction_sync",
		"after_transaction_sync",
		"before_destination_open",
		"after_destination_open",
		"before_object_publish",
		"after_object_publish",
		"before_object_parent_sync",
		"after_object_parent_sync",
		"before_destination_close",
		"after_destination_close",
		"manifest_before_temp_create",
		"manifest_after_temp_create",
		"manifest_after_temp_write",
		"manifest_after_temp_sync",
	} {
		t.Run(checkpoint, func(t *testing.T) {
			root := t.TempDir()
			fail := true
			store := openTestStore(t, StoreOptions{
				Root: root, RequiredUID: -1,
				Checkpoint: func(name string) error {
					if fail && name == checkpoint {
						return errors.New("injected publication fault")
					}
					return nil
				},
			})
			firstData := append(validOpenVPNProfile(), []byte("# first\n")...)
			secondData := append(validOpenVPNProfile(), []byte("# second\n")...)
			first := testProfile(t, ProtocolOpenVPN, firstData, 31)
			second := testProfile(t, ProtocolOpenVPN, secondData, 32)
			if _, err := store.Publish(0, []NewObject{{Profile: first, Bytes: firstData}, {Profile: second, Bytes: secondData}}); err == nil {
				t.Fatal("publication unexpectedly succeeded")
			}
			if len(store.List()) != 0 {
				t.Fatal("failed publication became manifest-visible")
			}
			fail = false
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
			if err != nil {
				t.Fatal(err)
			}
			defer reloaded.Close()
			if len(reloaded.List()) != 0 {
				t.Fatal("failed publication became visible after reopen")
			}
			for _, profile := range []Profile{first, second} {
				if _, err := os.Stat(reloaded.ObjectPath(profile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("orphan %s survived reopen: %v", profile.ID, err)
				}
			}
			assertDirectoryEmpty(t, filepath.Join(root, "library", ".transactions"))
			assertDirectoryEmpty(t, filepath.Join(root, "library", ".garbage"))
		})
	}
}

func TestStorePublishedManifestFaultMatrixReopensToCandidate(t *testing.T) {
	for _, checkpoint := range []string{"manifest_after_publish", "manifest_after_parent_sync"} {
		t.Run(checkpoint, func(t *testing.T) {
			root := t.TempDir()
			fail := true
			store := openTestStore(t, StoreOptions{
				Root: root, RequiredUID: -1,
				Checkpoint: func(name string) error {
					if fail && name == checkpoint {
						return errors.New("injected manifest durability fault")
					}
					return nil
				},
			})
			data := validOpenVPNProfile()
			profile := testProfile(t, ProtocolOpenVPN, data, 33)
			result, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}})
			if !errors.Is(err, ErrOutcomeAmbiguous) {
				t.Fatalf("publication returned %v", err)
			}
			if !result.CleanupPending || len(result.Manifest.Profiles) != 1 {
				t.Fatalf("ambiguous publication result = %+v", result)
			}
			if len(store.List()) != 1 {
				t.Fatal("published candidate was not adopted in memory")
			}
			fail = false
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
			if err != nil {
				t.Fatal(err)
			}
			defer reloaded.Close()
			if profiles := reloaded.List(); len(profiles) != 1 || profiles[0].ID != profile.ID {
				t.Fatalf("reopened candidate = %+v", profiles)
			}
		})
	}
}

func TestStorePostPublicationCleanupFaultsAreExplicitAndConverge(t *testing.T) {
	for _, checkpoint := range []string{
		"before_transaction_close",
		"after_transaction_close",
		"before_transaction_remove",
		"after_transaction_remove",
		"before_transactions_sync",
		"after_transactions_sync",
		"before_transactions_close",
		"after_transactions_close",
	} {
		t.Run(checkpoint, func(t *testing.T) {
			root := t.TempDir()
			fail := true
			store := openTestStore(t, StoreOptions{
				Root: root, RequiredUID: -1,
				Checkpoint: func(name string) error {
					if fail && name == checkpoint {
						return errors.New("injected cleanup fault")
					}
					return nil
				},
			})
			data := validOpenVPNProfile()
			profile := testProfile(t, ProtocolOpenVPN, data, 35)
			result, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}})
			if err != nil {
				t.Fatalf("Publish() error = %v", err)
			}
			if !result.CleanupPending || len(result.Manifest.Profiles) != 1 || result.Manifest.Profiles[0].ID != profile.ID {
				t.Fatalf("cleanup result = %+v", result)
			}
			fail = false
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
			if err != nil {
				t.Fatal(err)
			}
			defer reloaded.Close()
			if profiles := reloaded.List(); len(profiles) != 1 || profiles[0].ID != profile.ID {
				t.Fatalf("reopened profiles = %+v", profiles)
			}
			assertDirectoryEmpty(t, filepath.Join(root, "library", ".transactions"))
		})
	}
}

func TestStorePublishedButUnsyncedIsAmbiguousAndRepairable(t *testing.T) {
	fail := true
	store := openTestStore(t, StoreOptions{
		RequiredUID: -1,
		Checkpoint: func(name string) error {
			if fail && name == "manifest_after_publish" {
				return errors.New("injected parent sync failure")
			}
			return nil
		},
	})
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 4)
	_, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}})
	if !errors.Is(err, ErrOutcomeAmbiguous) {
		t.Fatalf("want ambiguous outcome, got %v", err)
	}
	if len(store.List()) != 1 {
		t.Fatal("published candidate was not adopted in memory")
	}
	fail = false
	if err := store.RepairDurability(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(profile.ID, fixedTestTime.Unix(), true); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRemovalIsManifestFirstAndCleansReferences(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 5)
	if _, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPreferences([]string{profile.ID}, []string{profile.ID}, StartupRestore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetConnection(profile.ID, fixedTestTime.Unix(), true); err != nil {
		t.Fatal(err)
	}
	removed, err := store.Remove(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Profile.ID != profile.ID || removed.CleanupPending {
		t.Fatalf("unexpected removal: %+v", removed)
	}
	manifest := store.Snapshot()
	if len(manifest.Profiles) != 0 || len(manifest.Favorites) != 0 || len(manifest.Recents) != 0 || manifest.DesiredProfile != "" || manifest.ConnectedAt != 0 {
		t.Fatalf("references survived removal: %+v", manifest)
	}
	if _, err := os.Stat(store.ObjectPath(profile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed object still exists: %v", err)
	}
}

func TestStoreRemovalFaultMatrixKeepsDeletionVisibleAndConverges(t *testing.T) {
	for _, checkpoint := range []string{
		"removal_before_quarantine",
		"removal_after_quarantine",
		"removal_after_parent_sync",
		"removal_after_cleanup",
		"removal_after_garbage_sync",
	} {
		t.Run(checkpoint, func(t *testing.T) {
			root := t.TempDir()
			fail := true
			store := openTestStore(t, StoreOptions{
				Root: root, RequiredUID: -1,
				Checkpoint: func(name string) error {
					if fail && name == checkpoint {
						return errors.New("injected removal fault")
					}
					return nil
				},
			})
			data := validOpenVPNProfile()
			profile := testProfile(t, ProtocolOpenVPN, data, 34)
			if _, err := store.Publish(0, []NewObject{{Profile: profile, Bytes: data}}); err != nil {
				t.Fatal(err)
			}
			removed, err := store.Remove(profile.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !removed.CleanupPending || len(store.List()) != 0 {
				t.Fatalf("removal result = %+v, profiles = %+v", removed, store.List())
			}
			fail = false
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenStore(StoreOptions{Root: root, RequiredUID: os.Getuid()})
			if err != nil {
				t.Fatal(err)
			}
			defer reloaded.Close()
			if len(reloaded.List()) != 0 {
				t.Fatal("removed profile reappeared after reopen")
			}
			if _, err := os.Stat(reloaded.ObjectPath(profile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("removed object survived reopen: %v", err)
			}
			assertDirectoryEmpty(t, filepath.Join(root, "library", ".garbage"))
		})
	}
}

func assertDirectoryEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s contains %d entries", path, len(entries))
	}
}

func TestStoreRejectsStaleRevisionAndMutationInReadOnlyMode(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	data := validOpenVPNProfile()
	profile := testProfile(t, ProtocolOpenVPN, data, 6)
	if _, err := store.Publish(1, []NewObject{{Profile: profile, Bytes: data}}); !errors.Is(err, ErrStaleInspection) {
		t.Fatalf("want stale inspection, got %v", err)
	}
	root := t.TempDir()
	readOnly := openTestStore(t, StoreOptions{Root: root, RequiredUID: -1, ReadOnly: true})
	if _, err := readOnly.SetPreferences(nil, nil, StartupManual); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("want read-only error, got %v", err)
	}
}
