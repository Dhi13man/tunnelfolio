package profiles

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestImporter(t *testing.T, store *Store, now *time.Time, checker CompatibilityChecker) *ImportService {
	t.Helper()
	if checker == nil {
		checker = CompatibilityCheckFunc(func([]byte) error { return nil })
	}
	seed := bytes.Repeat([]byte{0x21}, 32)
	for value := 0; value < 256; value++ {
		seed = append(seed, bytes.Repeat([]byte{byte(value)}, 16)...)
	}
	service, err := NewImportService(ImportServiceOptions{
		Store: store, Random: bytes.NewReader(seed), Now: func() time.Time { return *now },
		WireGuardChecker: checker,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestImportInspectCommitAndReplay(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	files := []ImportFile{{Name: "japan.conf", Bytes: validWireGuardProfile(10)}}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.CommitReady || inspection.Receipt == "" || inspection.InspectionRecords[0].Disposition != "new" {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}
	if encoded, _ := base64.RawURLEncoding.DecodeString(inspection.Receipt); len(encoded) != 41 {
		t.Fatalf("receipt envelope length = %d", len(encoded))
	}
	request := CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision,
		InspectionRecords: inspection.InspectionRecords, Receipt: inspection.Receipt,
		Metadata:           map[int]Metadata{0: {DisplayName: "Japan", Group: "Mullvad", Location: "JP"}},
		TrustProfilePolicy: true,
	}
	committed, err := service.Commit(request)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Replayed || len(committed.Records) != 1 || committed.Records[0].Result != "imported" {
		t.Fatalf("unexpected commit: %+v", committed)
	}
	stored, err := store.Resolve(committed.Records[0].Profile.ID)
	if err != nil || stored.DisplayName != "Japan" || stored.Group != "Mullvad" || stored.Location != "JP" {
		t.Fatalf("stored metadata = %+v, %v", stored, err)
	}
	replay, err := service.Commit(request)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Records[0].Profile.ID != stored.ID {
		t.Fatalf("unexpected replay: %+v", replay)
	}
}

func TestImportMetadataIsNotReceiptBoundButIdentityIs(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	files := []ImportFile{{Name: "work.ovpn", Bytes: validOpenVPNProfile()}}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	request := CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision, InspectionRecords: inspection.InspectionRecords,
		Metadata: map[int]Metadata{0: {DisplayName: "Edited after review", Group: "Work"}},
		Receipt:  inspection.Receipt, TrustProfilePolicy: true,
	}
	if _, err := service.Commit(request); err != nil {
		t.Fatalf("metadata edit invalidated receipt: %v", err)
	}

	otherStore := openTestStore(t, StoreOptions{RequiredUID: -1})
	otherService := newTestImporter(t, otherStore, &now, nil)
	otherInspection, err := otherService.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	otherInspection.InspectionRecords[0].Identifier = "tfaaaaaaaaaaaa"
	_, err = otherService.Commit(CommitRequest{
		Files: files, LibraryRevision: otherInspection.LibraryRevision, InspectionRecords: otherInspection.InspectionRecords,
		Metadata: map[int]Metadata{0: {DisplayName: "Work", Group: "Work"}}, Receipt: otherInspection.Receipt, TrustProfilePolicy: true,
	})
	if !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered identity returned %v", err)
	}
}

func TestImportReceiptExpiryTamperAndRestart(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	files := []ImportFile{{Name: "work.ovpn", Bytes: validOpenVPNProfile()}}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	request := CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision, InspectionRecords: inspection.InspectionRecords,
		Metadata: map[int]Metadata{0: {DisplayName: "Work", Group: "Work"}}, Receipt: inspection.Receipt, TrustProfilePolicy: true,
	}
	tampered := request
	replacement := byte('A')
	if request.Receipt[len(request.Receipt)-1] == replacement {
		replacement = 'B'
	}
	tampered.Receipt = request.Receipt[:len(request.Receipt)-1] + string(replacement)
	if _, err := service.Commit(tampered); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered receipt returned %v", err)
	}
	now = inspection.ExpiresAt.Add(time.Second)
	if _, err := service.Commit(request); !errors.Is(err, ErrExpiredReceipt) {
		t.Fatalf("expired receipt returned %v", err)
	}
	now = fixedTestTime
	restarted, err := NewImportService(ImportServiceOptions{
		Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 32+16*256)),
		Now: func() time.Time { return now }, WireGuardChecker: CompatibilityCheckFunc(func([]byte) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Commit(request); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("receipt survived process key rotation: %v", err)
	}
}

func TestImportStaleReceiptDoesNotRecreateRemovedOrCrossMutation(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	files := []ImportFile{
		{Name: "work.ovpn", Bytes: joined(validOpenVPNProfile(), "# work profile\n")},
		{Name: "home.ovpn", Bytes: joined(validOpenVPNProfile(), "# home profile\n")},
	}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	request := CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision, InspectionRecords: inspection.InspectionRecords,
		Metadata: map[int]Metadata{
			0: {DisplayName: "Work", Group: "Imported"},
			1: {DisplayName: "Home", Group: "Imported"},
		},
		Receipt: inspection.Receipt, TrustProfilePolicy: true,
	}
	committed, err := service.Commit(request)
	if err != nil {
		t.Fatal(err)
	}
	removed := committed.Records[0].Profile
	retained := committed.Records[1].Profile
	if _, err := store.Remove(removed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Commit(request); !errors.Is(err, ErrStaleInspection) {
		t.Fatalf("stale inspection returned %v", err)
	}
	if _, err := store.Resolve(removed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed profile was recreated: %v", err)
	}
	if _, err := os.Stat(store.ObjectPath(removed)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed profile object was recreated: %v", err)
	}
	if profiles := store.List(); len(profiles) != 1 || profiles[0].ID != retained.ID {
		t.Fatalf("mixed-batch replay changed retained profiles: %+v", profiles)
	}
}

func TestImportDuplicateWithinBatchIsOneObjectAndStableResults(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	data := validOpenVPNProfile()
	files := []ImportFile{{Name: "one.ovpn", Bytes: data}, {Name: "copy.ovpn", Bytes: append([]byte(nil), data...)}}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.InspectionRecords[0].Disposition != "new" || inspection.InspectionRecords[1].Disposition != "already_imported" ||
		inspection.InspectionRecords[0].ID != inspection.InspectionRecords[1].ID {
		t.Fatalf("unexpected duplicate plan: %+v", inspection.InspectionRecords)
	}
	result, err := service.Commit(CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision, InspectionRecords: inspection.InspectionRecords,
		Metadata: map[int]Metadata{0: {DisplayName: "One", Group: "Tests"}, 1: {DisplayName: "Ignored", Group: "Tests"}},
		Receipt:  inspection.Receipt, TrustProfilePolicy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.List()) != 1 || result.Records[0].Profile.ID != result.Records[1].Profile.ID || result.Records[1].Result != "already_imported" {
		t.Fatalf("duplicate commit was not idempotent: %+v", result)
	}
}

func TestImportInspectionReturnsSafeIssuesWithoutReceipt(t *testing.T) {
	for _, protocol := range []string{ProtocolOpenVPN, ProtocolWireGuard} {
		t.Run(protocol, func(t *testing.T) {
			store := openTestStore(t, StoreOptions{RequiredUID: -1})
			now := fixedTestTime
			service := newTestImporter(t, store, &now, nil)
			marker := filepath.Join(t.TempDir(), "executed")
			filename := "unsafe.ovpn"
			data := append(validOpenVPNProfile(), []byte("up touch "+marker+"\n")...)
			if protocol == ProtocolWireGuard {
				filename = "unsafe.conf"
				data = append(validWireGuardProfile(20), []byte("PostUp = touch "+marker+"\n")...)
			}
			inspection, err := service.Inspect([]ImportFile{{Name: filename, Bytes: data}})
			if err != nil {
				t.Fatal(err)
			}
			if inspection.CommitReady || inspection.Receipt != "" || len(inspection.InspectionRecords[0].Issues) != 1 {
				t.Fatalf("unsafe profile was commit-ready: %+v", inspection)
			}
			if strings.Contains(inspection.InspectionRecords[0].Issues[0].Message, marker) {
				t.Fatal("policy issue exposed uploaded content")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("profile hook executed during inspection: %v", err)
			}
		})
	}
}

func TestImportPolicyIssueDoesNotEchoUnknownUploadedToken(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	service := newTestImporter(t, store, &now, nil)
	canary := "credential-canary-should-not-escape"
	inspection, err := service.Inspect([]ImportFile{{Name: "unknown.ovpn", Bytes: joined(validOpenVPNProfile(), canary+" yes\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.InspectionRecords[0].Issues) != 1 {
		t.Fatalf("issues = %+v", inspection.InspectionRecords[0].Issues)
	}
	if strings.Contains(inspection.InspectionRecords[0].Issues[0].Message, canary) {
		t.Fatal("unknown uploaded token escaped through the policy response")
	}
}

func TestImportGateRejectsConcurrentInspection(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	service := newTestImporter(t, store, &now, CompatibilityCheckFunc(func([]byte) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}))
	done := make(chan error, 1)
	go func() {
		_, err := service.Inspect([]ImportFile{{Name: "one.conf", Bytes: validWireGuardProfile(12)}})
		done <- err
	}()
	<-entered
	_, err := service.Inspect([]ImportFile{{Name: "two.conf", Bytes: validWireGuardProfile(13)}})
	if !errors.Is(err, ErrImportBusy) {
		t.Fatalf("concurrent inspection returned %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestImportCommitHonorsLifecycleAdmission(t *testing.T) {
	store := openTestStore(t, StoreOptions{RequiredUID: -1})
	now := fixedTestTime
	blocked := true
	service, err := NewImportService(ImportServiceOptions{
		Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 32+16*16)), Now: func() time.Time { return now },
		WireGuardChecker: CompatibilityCheckFunc(func([]byte) error { return nil }),
		CommitAdmission: func() (func(), error) {
			if blocked {
				return nil, errors.New("transition in progress")
			}
			return func() {}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := []ImportFile{{Name: "office.ovpn", Bytes: validOpenVPNProfile()}}
	inspection, err := service.Inspect(files)
	if err != nil {
		t.Fatal(err)
	}
	request := CommitRequest{
		Files: files, LibraryRevision: inspection.LibraryRevision, InspectionRecords: inspection.InspectionRecords,
		Metadata: map[int]Metadata{0: {DisplayName: "Office", Group: "Work"}}, Receipt: inspection.Receipt, TrustProfilePolicy: true,
	}
	if _, err := service.Commit(request); err == nil {
		t.Fatal("commit bypassed lifecycle admission")
	}
	blocked = false
	if _, err := service.Commit(request); err != nil {
		t.Fatal(err)
	}
}
