package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type WGCommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type WireGuardMetrics struct {
	ReceivedBytes uint64 `json:"received_bytes"`
	SentBytes     uint64 `json:"sent_bytes"`
}

type WireGuardBackend struct {
	catalog      *ProfileCatalog
	runner       WGCommandRunner
	pollInterval time.Duration
}

func NewWireGuardBackend(catalog *ProfileCatalog, runner WGCommandRunner, pollInterval time.Duration) *WireGuardBackend {
	return &WireGuardBackend{catalog: catalog, runner: runner, pollInterval: pollInterval}
}

func (b *WireGuardBackend) Available(ctx context.Context) error {
	if _, err := b.catalog.Profiles(BackendWireGuard); err != nil {
		return err
	}
	if _, err := b.runner.Run(ctx, "wg", "show", "interfaces"); err != nil {
		return fmt.Errorf("query WireGuard interfaces: %w", err)
	}
	return nil
}

func (b *WireGuardBackend) Observe(ctx context.Context) ([]CatalogProfile, error) {
	profiles, err := b.catalog.Profiles(BackendWireGuard)
	if err != nil {
		return nil, err
	}
	output, err := b.runner.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return nil, fmt.Errorf("query WireGuard interfaces: %w", err)
	}

	byInterface := make(map[string][]CatalogProfile, len(profiles))
	for _, profile := range profiles {
		byInterface[profile.Identifier] = append(byInterface[profile.Identifier], profile)
	}
	active := make([]CatalogProfile, 0, 1)
	for _, interfaceName := range strings.Fields(string(output)) {
		matches := byInterface[interfaceName]
		if len(matches) > 1 {
			return nil, fmt.Errorf("interface %s maps to multiple catalog profiles", interfaceName)
		}
		active = append(active, matches...)
	}
	return active, nil
}

func (b *WireGuardBackend) Start(ctx context.Context, profile CatalogProfile) error {
	resolved, err := b.catalog.Resolve(profile.ID)
	if err != nil {
		return err
	}
	if resolved.Backend != BackendWireGuard {
		return errors.New("profile does not use the WireGuard backend")
	}
	if _, err := b.runner.Run(ctx, "wg-quick", "up", resolved.Path); err != nil {
		return b.cleanupFailedStart(resolved, fmt.Errorf("start WireGuard profile %s: %w", resolved.ID, err))
	}
	if err := b.waitForInterface(ctx, resolved.Identifier, true); err != nil {
		return b.cleanupFailedStart(resolved, fmt.Errorf("prove WireGuard profile %s ready: %w", resolved.ID, err))
	}
	return nil
}

func (b *WireGuardBackend) cleanupFailedStart(profile CatalogProfile, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	present, observeErr := b.interfacePresent(cleanupCtx, profile.Identifier)
	if observeErr == nil && !present {
		return cause
	}
	_, downErr := b.runner.Run(cleanupCtx, "wg-quick", "down", profile.Path)
	if downErr == nil {
		downErr = b.waitForInterface(cleanupCtx, profile.Identifier, false)
	}
	if downErr != nil {
		return fmt.Errorf("%w; cleanup failed: %v", cause, errors.Join(observeErr, downErr))
	}
	return cause
}

func (b *WireGuardBackend) Stop(ctx context.Context, profile CatalogProfile) error {
	resolved, err := b.catalog.Resolve(profile.ID)
	if err != nil {
		return err
	}
	if resolved.Backend != BackendWireGuard {
		return errors.New("profile does not use the WireGuard backend")
	}
	present, err := b.interfacePresent(ctx, resolved.Identifier)
	if err != nil {
		return fmt.Errorf("inspect WireGuard profile %s before stopping: %w", resolved.ID, err)
	}
	if !present {
		return nil
	}
	if _, err := b.runner.Run(ctx, "wg-quick", "down", resolved.Path); err != nil {
		return fmt.Errorf("stop WireGuard profile %s: %w", resolved.ID, err)
	}
	if err := b.waitForInterface(ctx, resolved.Identifier, false); err != nil {
		return fmt.Errorf("prove WireGuard profile %s stopped: %w", resolved.ID, err)
	}
	return nil
}

func (b *WireGuardBackend) Metrics(ctx context.Context, profile CatalogProfile) (WireGuardMetrics, error) {
	resolved, err := b.catalog.Resolve(profile.ID)
	if err != nil {
		return WireGuardMetrics{}, err
	}
	if resolved.Backend != BackendWireGuard {
		return WireGuardMetrics{}, errors.New("profile does not use the WireGuard backend")
	}
	output, err := b.runner.Run(ctx, "wg", "show", resolved.Identifier, "dump")
	if err != nil {
		return WireGuardMetrics{}, fmt.Errorf("query WireGuard metrics: %w", err)
	}
	return parseWireGuardMetrics(output)
}

func (b *WireGuardBackend) waitForInterface(ctx context.Context, interfaceName string, present bool) error {
	for {
		seen, err := b.interfacePresent(ctx, interfaceName)
		if err != nil {
			return err
		}
		if seen == present {
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

func (b *WireGuardBackend) interfacePresent(ctx context.Context, interfaceName string) (bool, error) {
	output, err := b.runner.Run(ctx, "wg", "show", "interfaces")
	if err != nil {
		return false, fmt.Errorf("query WireGuard interfaces: %w", err)
	}
	for _, candidate := range strings.Fields(string(output)) {
		if candidate == interfaceName {
			return true, nil
		}
	}
	return false, nil
}

func parseWireGuardMetrics(output []byte) (WireGuardMetrics, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || len(lines[0]) == 0 {
		return WireGuardMetrics{}, errors.New("empty WireGuard dump")
	}
	if len(strings.Split(lines[0], "\t")) < 4 {
		return WireGuardMetrics{}, errors.New("malformed WireGuard interface row")
	}
	var metrics WireGuardMetrics
	for index, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			return WireGuardMetrics{}, fmt.Errorf("malformed WireGuard peer row %d", index+1)
		}
		received, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return WireGuardMetrics{}, fmt.Errorf("parse received bytes in peer row %d: %w", index+1, err)
		}
		sent, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return WireGuardMetrics{}, fmt.Errorf("parse sent bytes in peer row %d: %w", index+1, err)
		}
		if math.MaxUint64-metrics.ReceivedBytes < received || math.MaxUint64-metrics.SentBytes < sent {
			return WireGuardMetrics{}, errors.New("WireGuard transfer counters overflow")
		}
		metrics.ReceivedBytes += received
		metrics.SentBytes += sent
	}
	return metrics, nil
}
