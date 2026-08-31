package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
)

type backendMetrics map[string]any

type managedBackend interface {
	Kind() string
	Enabled() bool
	Availability(context.Context) error
	Observe(context.Context) ([]CatalogProfile, error)
	Start(context.Context, CatalogProfile) error
	Stop(context.Context, CatalogProfile) error
	Metrics(context.Context, CatalogProfile) (backendMetrics, error)
	Shutdown(context.Context) error
}

type wireGuardAdapter struct {
	backend *WireGuardBackend
}

func (a *wireGuardAdapter) Kind() string  { return BackendWireGuard }
func (a *wireGuardAdapter) Enabled() bool { return true }

func (a *wireGuardAdapter) Availability(ctx context.Context) error {
	return a.backend.Available(ctx)
}

func (a *wireGuardAdapter) Observe(ctx context.Context) ([]CatalogProfile, error) {
	return a.backend.Observe(ctx)
}

func (a *wireGuardAdapter) Start(ctx context.Context, profile CatalogProfile) error {
	return a.backend.Start(ctx, profile)
}

func (a *wireGuardAdapter) Stop(ctx context.Context, profile CatalogProfile) error {
	return a.backend.Stop(ctx, profile)
}

func (a *wireGuardAdapter) Metrics(ctx context.Context, profile CatalogProfile) (backendMetrics, error) {
	metrics, err := a.backend.Metrics(ctx, profile)
	if err != nil {
		return nil, err
	}
	return backendMetrics{"received_bytes": metrics.ReceivedBytes, "sent_bytes": metrics.SentBytes}, nil
}

func (a *wireGuardAdapter) Shutdown(context.Context) error { return nil }

type openVPNAdapter struct {
	backend *OpenVPNBackend
	catalog *ProfileCatalog

	mu      sync.Mutex
	current *CatalogProfile
}

func (a *openVPNAdapter) Kind() string  { return BackendOpenVPN }
func (a *openVPNAdapter) Enabled() bool { return true }

func (a *openVPNAdapter) Availability(context.Context) error {
	_, err := a.catalog.Profiles(BackendOpenVPN)
	return err
}

func (a *openVPNAdapter) Observe(context.Context) ([]CatalogProfile, error) {
	state := a.backend.State()
	if state.GroupPresent && (!state.Running || !state.Ready) {
		return nil, fmt.Errorf("OpenVPN process is in an unmanaged lifecycle state: %s", state.LastError)
	}
	if !state.Running || !state.Ready {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return nil, errors.New("OpenVPN process is active without a catalog profile")
	}
	profile := *a.current
	return []CatalogProfile{profile}, nil
}

func (a *openVPNAdapter) LastError() string { return a.backend.State().LastError }

func (a *openVPNAdapter) Start(ctx context.Context, profile CatalogProfile) error {
	if profile.Backend != BackendOpenVPN {
		return errors.New("profile does not use the OpenVPN backend")
	}
	if err := a.backend.Activate(ctx, profile.Path, filepath.Dir(profile.Path)); err != nil {
		return err
	}
	a.mu.Lock()
	a.current = &profile
	a.mu.Unlock()
	return nil
}

func (a *openVPNAdapter) Stop(ctx context.Context, _ CatalogProfile) error {
	if err := a.backend.Deactivate(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.current = nil
	a.mu.Unlock()
	return nil
}

func (a *openVPNAdapter) Metrics(context.Context, CatalogProfile) (backendMetrics, error) {
	return nil, nil
}

func (a *openVPNAdapter) Shutdown(ctx context.Context) error {
	return a.Stop(ctx, CatalogProfile{})
}

type unavailableBackend struct {
	kind string
	err  error
}

func (b unavailableBackend) Kind() string  { return b.kind }
func (b unavailableBackend) Enabled() bool { return false }

func (b unavailableBackend) Availability(context.Context) error { return b.err }

func (b unavailableBackend) Observe(context.Context) ([]CatalogProfile, error) { return nil, nil }

func (b unavailableBackend) Start(context.Context, CatalogProfile) error {
	return fmt.Errorf("%w: %s: %v", ErrBackendUnavailable, b.kind, b.err)
}

func (b unavailableBackend) Stop(context.Context, CatalogProfile) error { return nil }

func (b unavailableBackend) Metrics(context.Context, CatalogProfile) (backendMetrics, error) {
	return nil, b.err
}

func (b unavailableBackend) Shutdown(context.Context) error { return nil }
