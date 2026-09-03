package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandCall struct {
	name string
	args []string
}

type fakeWireGuardRunner struct {
	interfaces map[string]string
	dumps      map[string][]byte
	fail       map[string]error
	calls      []commandCall
}

func (r *fakeWireGuardRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	key := name + " " + strings.Join(args, " ")
	if err := r.fail[key]; err != nil {
		return nil, err
	}
	if name == "wg" && reflect.DeepEqual(args, []string{"show", "interfaces"}) {
		names := make([]string, 0, len(r.interfaces))
		for name := range r.interfaces {
			names = append(names, name)
		}
		return []byte(strings.Join(names, " ")), nil
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "public-key" {
		key, found := r.interfaces[args[1]]
		if !found {
			return nil, errors.New("missing interface")
		}
		return []byte(key + "\n"), nil
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "dump" {
		return r.dumps[args[1]], nil
	}
	if name == "wg-quick" && len(args) == 2 {
		profile := testWireGuardRuntimeProfile(1)
		if args[1] != profile.Path {
			return nil, fmt.Errorf("unexpected path")
		}
		switch args[0] {
		case "up":
			r.interfaces[profile.Identifier] = testPublicKey(1)
		case "down":
			delete(r.interfaces, profile.Identifier)
		default:
			return nil, errors.New("unexpected wg-quick action")
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %s", key)
}

func testPublicKey(seed byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed + 1}), 32)))
}

func testWireGuardRuntimeProfile(seed byte) Profile {
	encoded := testPublicKey(seed)
	key, _ := base64.StdEncoding.DecodeString(encoded)
	digest := sha256.Sum256(key)
	return Profile{
		ID: "tf_test", Protocol: ProtocolWireGuard, Identifier: "tfexample12345", Path: "/state/tfexample12345.conf",
		WireGuardPublicKeySHA256: hex.EncodeToString(digest[:]),
	}
}

func TestWireGuardObserveRequiresNameAndKeyIdentity(t *testing.T) {
	profile := testWireGuardRuntimeProfile(1)
	runner := &fakeWireGuardRunner{interfaces: map[string]string{profile.Identifier: testPublicKey(1), "unmanaged": testPublicKey(8)}, fail: map[string]error{}}
	backend := NewWireGuardBackend(runner, 0)
	observed, err := backend.Observe(context.Background(), []Profile{profile})
	if err != nil || len(observed) != 1 || observed[0].ProfileID != profile.ID {
		t.Fatalf("observation = %+v, %v", observed, err)
	}
	runner.interfaces[profile.Identifier] = testPublicKey(9)
	if _, err := backend.Observe(context.Background(), []Profile{profile}); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("key mismatch returned %v", err)
	}
}

func TestWireGuardObservationBackendSeparatesObservationFromActivation(t *testing.T) {
	profile := testWireGuardRuntimeProfile(1)
	runner := &fakeWireGuardRunner{interfaces: map[string]string{profile.Identifier: testPublicKey(1)}, fail: map[string]error{}}
	backend := NewWireGuardObservationBackend(runner)
	observed, err := backend.Observe(context.Background(), []Profile{profile})
	if err != nil || len(observed) != 1 || observed[0].ProfileID != profile.ID {
		t.Fatalf("observation = %+v, %v", observed, err)
	}
	if err := backend.Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("activation availability = %v", err)
	}
	if err := backend.Start(context.Background(), profile); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("observation-only start = %v", err)
	}
}

func TestWireGuardStartStopAndRefuseForeignIdentity(t *testing.T) {
	profile := testWireGuardRuntimeProfile(1)
	runner := &fakeWireGuardRunner{interfaces: map[string]string{}, fail: map[string]error{}}
	backend := NewWireGuardBackend(runner, 0)
	if err := backend.Start(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if err := backend.Stop(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	runner.interfaces[profile.Identifier] = testPublicKey(7)
	before := len(runner.calls)
	if err := backend.Stop(context.Background(), profile); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("foreign stop returned %v", err)
	}
	for _, call := range runner.calls[before:] {
		if call.name == "wg-quick" {
			t.Fatal("foreign interface was passed to wg-quick down")
		}
	}
}

func TestWireGuardFailedStartCleansOnlyMatchingNewInterface(t *testing.T) {
	profile := testWireGuardRuntimeProfile(1)
	upKey := "wg-quick up " + profile.Path
	runner := &fakeWireGuardRunner{interfaces: map[string]string{}, fail: map[string]error{upKey: errors.New("failed after create")}}
	backend := NewWireGuardBackend(runner, 0)
	// Simulate a tool that created the expected interface before returning an error.
	runner.interfaces[profile.Identifier] = testPublicKey(1)
	if err := backend.cleanupFailedStart(profile, errors.New("activation failed")); err == nil {
		t.Fatal("cleanup hid the activation failure")
	}
	if _, exists := runner.interfaces[profile.Identifier]; exists {
		t.Fatal("matching partial interface survived cleanup")
	}
	runner.interfaces[profile.Identifier] = testPublicKey(9)
	if err := backend.cleanupFailedStart(profile, errors.New("activation failed")); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("foreign cleanup returned %v", err)
	}
	if _, exists := runner.interfaces[profile.Identifier]; !exists {
		t.Fatal("foreign interface was removed")
	}
}

func TestParseWireGuardDumpKeepsOnlySafeStatus(t *testing.T) {
	interfaceRow := "private\tpublic\t51820\toff"
	peerOne := "public-one\tpsk\t203.0.113.8:51820\t0.0.0.0/0\t1700000000\t12\t34\t25"
	peerTwo := "public-two\tpsk\t[2001:db8::1]:51820\t::/0\t0\t56\t78\t0"
	status, err := parseWireGuardDump([]byte(interfaceRow + "\n" + peerOne + "\n" + peerTwo + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if status.ReceivedBytes != 68 || status.SentBytes != 112 || len(status.Peers) != 2 || status.Peers[0].LatestHandshake != 1700000000 {
		t.Fatalf("status = %+v", status)
	}
	formatted := fmt.Sprintf("%+v", status)
	if strings.Contains(formatted, "public-one") || strings.Contains(formatted, "psk") {
		t.Fatal("status exposed a key")
	}
}

func TestWireGuardWaitHonorsCancellation(t *testing.T) {
	profile := testWireGuardRuntimeProfile(1)
	runner := &fakeWireGuardRunner{interfaces: map[string]string{}, fail: map[string]error{}}
	backend := NewWireGuardBackend(runner, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := backend.waitForProfile(ctx, profile, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait returned %v", err)
	}
}
