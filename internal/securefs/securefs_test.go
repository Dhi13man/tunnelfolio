package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDirectoryAndFileRejectSymlinksAndLooseModes(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "private")
	if err := EnsurePrivateDir(private, -1); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(private, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPrivateDir(filepath.Join(private, "linked"), -1); err == nil {
		t.Fatal("symlinked directory was accepted")
	}
	loose := filepath.Join(private, "loose")
	if err := os.WriteFile(loose, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(loose, 32, -1); err == nil {
		t.Fatal("loosely permissioned file was accepted")
	}
}

func TestLifetimeLockExclusion(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireLock(root, -1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AcquireLock(root, -1)
	if second != nil {
		_ = second.Close()
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := AcquireLock(root, -1)
	if err != nil {
		t.Fatal(err)
	}
	_ = third.Close()
}

func TestAtomicJSONReportsPublicationAndDurabilityBoundaries(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "state.json")
	result, err := WriteJSONAtomic(path, map[string]int{"version": 1}, -1, func(name string) error {
		if name == "after_publish" {
			return errors.New("injected sync failure")
		}
		return nil
	})
	if err == nil || !result.Published || result.Durable {
		t.Fatalf("unexpected boundary result: %+v, %v", result, err)
	}
	var stored map[string]int
	if err := ReadJSON(path, &stored, 1024, -1); err != nil {
		t.Fatal(err)
	}
	if stored["version"] != 1 {
		t.Fatalf("published value = %+v", stored)
	}
	result, err = WriteJSONAtomic(path, map[string]int{"version": 2}, -1, nil)
	if err != nil || !result.Published || !result.Durable {
		t.Fatalf("durable result: %+v, %v", result, err)
	}
}

func TestStrictJSONRejectsUnknownAndTrailingValues(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	type state struct {
		Version int `json:"version"`
	}
	for name, data := range map[string]string{
		"unknown":  `{"version":1,"extra":true}`,
		"trailing": `{"version":1}{"version":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			var value state
			if err := ReadJSON(path, &value, 1024, -1); err == nil {
				t.Fatal("invalid JSON was accepted")
			}
		})
	}
}
