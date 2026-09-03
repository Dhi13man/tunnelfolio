package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type WireGuardBackend struct {
	runner         CommandRunner
	pollInterval   time.Duration
	cleanupTimeout time.Duration
	canActivate    bool
}

func NewWireGuardBackend(runner CommandRunner, pollInterval time.Duration) *WireGuardBackend {
	return &WireGuardBackend{runner: runner, pollInterval: pollInterval, cleanupTimeout: DefaultTimeout, canActivate: true}
}

func NewWireGuardObservationBackend(runner CommandRunner) *WireGuardBackend {
	return &WireGuardBackend{runner: runner, cleanupTimeout: DefaultTimeout}
}

func (b *WireGuardBackend) Protocol() string { return ProtocolWireGuard }

func (b *WireGuardBackend) Available(ctx context.Context) error {
	if b.runner == nil {
		return ErrUnavailable
	}
	if _, err := b.runner.Run(ctx, "wg", "show", "interfaces"); err != nil {
		return fmt.Errorf("%w: query WireGuard interfaces", ErrUnavailable)
	}
	if !b.canActivate {
		return fmt.Errorf("%w: wg-quick is unavailable", ErrUnavailable)
	}
	return nil
}

func (b *WireGuardBackend) Observe(ctx context.Context, profiles []Profile) ([]Observation, error) {
	output, err := b.runner.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return nil, fmt.Errorf("%w: query WireGuard interfaces", ErrObservationFailed)
	}
	byIdentifier := make(map[string]Profile, len(profiles))
	for _, profile := range profiles {
		if profile.Protocol != ProtocolWireGuard {
			continue
		}
		if _, exists := byIdentifier[profile.Identifier]; exists {
			return nil, fmt.Errorf("%w: duplicate WireGuard runtime name", ErrIdentityConflict)
		}
		byIdentifier[profile.Identifier] = profile
	}
	active := make([]Observation, 0, 1)
	for _, interfaceName := range strings.Fields(string(output)) {
		profile, managed := byIdentifier[interfaceName]
		if !managed {
			continue
		}
		matches, err := b.identityMatches(ctx, profile)
		if err != nil {
			return nil, err
		}
		if !matches {
			return nil, fmt.Errorf("%w: WireGuard name exists with a different key", ErrIdentityConflict)
		}
		active = append(active, Observation{ProfileID: profile.ID, Protocol: profile.Protocol, Identifier: profile.Identifier})
	}
	return active, nil
}

func (b *WireGuardBackend) Start(ctx context.Context, profile Profile) error {
	if !b.canActivate {
		return ErrUnavailable
	}
	if err := validateWireGuardProfile(profile); err != nil {
		return err
	}
	present, err := b.interfacePresent(ctx, profile.Identifier)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("%w: WireGuard runtime name is already present", ErrIdentityConflict)
	}
	if _, err := b.runner.Run(ctx, "wg-quick", "up", profile.Path); err != nil {
		return b.cleanupFailedStart(profile, fmt.Errorf("start WireGuard profile %s: %w", profile.ID, err))
	}
	if err := b.waitForProfile(ctx, profile, true); err != nil {
		return b.cleanupFailedStart(profile, fmt.Errorf("prove WireGuard profile %s ready: %w", profile.ID, err))
	}
	return nil
}

func (b *WireGuardBackend) cleanupFailedStart(profile Profile, cause error) error {
	timeout := b.cleanupTimeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	present, observeErr := b.interfacePresent(ctx, profile.Identifier)
	if observeErr == nil && !present {
		return cause
	}
	if observeErr != nil {
		return errors.Join(cause, ErrCleanupUnproved, fmt.Errorf("cleanup observation failed: %w", observeErr))
	}
	matches, identityErr := b.identityMatches(ctx, profile)
	if identityErr != nil || !matches {
		return errors.Join(cause, ErrCleanupUnproved, fmt.Errorf("cleanup identity was not proved: %w", errors.Join(ErrIdentityConflict, identityErr)))
	}
	_, downErr := b.runner.Run(ctx, "wg-quick", "down", profile.Path)
	if downErr == nil {
		downErr = b.waitForProfile(ctx, profile, false)
	}
	if downErr != nil {
		return errors.Join(cause, ErrCleanupUnproved, fmt.Errorf("cleanup failed: %w", downErr))
	}
	return cause
}

func (b *WireGuardBackend) Stop(ctx context.Context, profile Profile) error {
	if !b.canActivate {
		return ErrUnavailable
	}
	if err := validateWireGuardProfile(profile); err != nil {
		return err
	}
	present, err := b.interfacePresent(ctx, profile.Identifier)
	if err != nil {
		return fmt.Errorf("inspect WireGuard profile before stopping: %w", err)
	}
	if !present {
		return nil
	}
	matches, err := b.identityMatches(ctx, profile)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("%w: refusing to stop key-mismatched WireGuard interface", ErrIdentityConflict)
	}
	if _, err := b.runner.Run(ctx, "wg-quick", "down", profile.Path); err != nil {
		return fmt.Errorf("stop WireGuard profile %s: %w", profile.ID, err)
	}
	if err := b.waitForProfile(ctx, profile, false); err != nil {
		return fmt.Errorf("prove WireGuard profile %s stopped: %w", profile.ID, err)
	}
	return nil
}

func (b *WireGuardBackend) Status(ctx context.Context, profile Profile) (ProtocolStatus, error) {
	if err := validateWireGuardProfile(profile); err != nil {
		return ProtocolStatus{}, err
	}
	output, err := b.runner.Run(ctx, "wg", "show", profile.Identifier, "dump")
	if err != nil {
		return ProtocolStatus{}, fmt.Errorf("query WireGuard status")
	}
	return parseWireGuardDump(output)
}

func (b *WireGuardBackend) Shutdown(context.Context) error { return nil }

func (b *WireGuardBackend) waitForProfile(ctx context.Context, profile Profile, present bool) error {
	for {
		seen, err := b.interfacePresent(ctx, profile.Identifier)
		if err != nil {
			return err
		}
		if seen == present {
			if !present {
				return nil
			}
			matches, err := b.identityMatches(ctx, profile)
			if err != nil {
				return err
			}
			if !matches {
				return ErrIdentityConflict
			}
			return nil
		}
		if b.pollInterval <= 0 {
			return errors.New("WireGuard interface did not reach expected state")
		}
		timer := time.NewTimer(b.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (b *WireGuardBackend) interfacePresent(ctx context.Context, identifier string) (bool, error) {
	output, err := b.runner.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return false, fmt.Errorf("query WireGuard interfaces: %w", err)
	}
	for _, candidate := range strings.Fields(string(output)) {
		if candidate == identifier {
			return true, nil
		}
	}
	return false, nil
}

func (b *WireGuardBackend) identityMatches(ctx context.Context, profile Profile) (bool, error) {
	output, err := b.runner.Run(ctx, "wg", "show", profile.Identifier, "public-key")
	if err != nil {
		return false, fmt.Errorf("%w: query WireGuard interface identity", ErrObservationFailed)
	}
	encoded := strings.TrimSpace(string(output))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		return false, fmt.Errorf("%w: malformed WireGuard public key", ErrObservationFailed)
	}
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:]) == profile.WireGuardPublicKeySHA256, nil
}

func validateWireGuardProfile(profile Profile) error {
	if profile.ID == "" || profile.Protocol != ProtocolWireGuard || profile.Identifier == "" || profile.Path == "" || len(profile.WireGuardPublicKeySHA256) != 64 {
		return errors.New("invalid WireGuard profile")
	}
	return nil
}

func parseWireGuardDump(output []byte) (ProtocolStatus, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" || len(strings.Split(lines[0], "\t")) != 4 {
		return ProtocolStatus{}, errors.New("malformed WireGuard interface row")
	}
	status := ProtocolStatus{State: "interface_active", Peers: []WireGuardPeerStatus{}}
	if len(lines)-1 > 32 {
		return ProtocolStatus{}, errors.New("WireGuard dump exceeds the managed peer limit")
	}
	for index, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 8 {
			return ProtocolStatus{}, fmt.Errorf("malformed WireGuard peer row %d", index+1)
		}
		handshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil || handshake < 0 {
			return ProtocolStatus{}, fmt.Errorf("malformed WireGuard handshake in peer row %d", index+1)
		}
		received, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return ProtocolStatus{}, fmt.Errorf("malformed WireGuard receive counter in peer row %d", index+1)
		}
		sent, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return ProtocolStatus{}, fmt.Errorf("malformed WireGuard send counter in peer row %d", index+1)
		}
		if math.MaxUint64-status.ReceivedBytes < received || math.MaxUint64-status.SentBytes < sent {
			return ProtocolStatus{}, errors.New("WireGuard transfer counters overflow")
		}
		status.ReceivedBytes += received
		status.SentBytes += sent
		status.Peers = append(status.Peers, WireGuardPeerStatus{
			Endpoint: fields[2], LatestHandshake: handshake, ReceivedBytes: received, SentBytes: sent,
		})
	}
	return status, nil
}
