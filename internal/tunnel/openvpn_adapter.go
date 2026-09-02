package tunnel

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
)

type OpenVPNAdapter struct {
	backend *OpenVPNBackend

	mu          sync.Mutex
	current     Profile
	exitHandler func(UnexpectedExit)
}

func NewOpenVPNAdapter(backend *OpenVPNBackend) (*OpenVPNAdapter, error) {
	if backend == nil {
		return nil, errors.New("OpenVPN backend is required")
	}
	adapter := &OpenVPNAdapter{backend: backend}
	backend.setUnexpectedExitHandler(adapter.unexpectedExit)
	return adapter, nil
}

func (a *OpenVPNAdapter) Protocol() string { return ProtocolOpenVPN }

func (a *OpenVPNAdapter) Available(context.Context) error { return nil }

func (a *OpenVPNAdapter) Observe(_ context.Context, profiles []Profile) ([]Observation, error) {
	state := a.backend.State()
	if state.GroupPresent && (!state.Running || !state.Ready) {
		return nil, errors.Join(ErrObservationFailed, errors.New("OpenVPN process is in an unsettled lifecycle state"))
	}
	if !state.Running || !state.Ready {
		return nil, nil
	}
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	if current.ID == "" {
		return nil, errors.Join(ErrIdentityConflict, errors.New("OpenVPN process is active without an owned profile identity"))
	}
	for _, profile := range profiles {
		if profile.ID == current.ID && profile.Protocol == ProtocolOpenVPN {
			return []Observation{{ProfileID: profile.ID, Protocol: profile.Protocol, Identifier: profile.Identifier}}, nil
		}
	}
	return nil, errors.Join(ErrIdentityConflict, errors.New("OpenVPN process profile no longer exists"))
}

func (a *OpenVPNAdapter) Start(ctx context.Context, profile Profile) error {
	if profile.ID == "" || profile.Protocol != ProtocolOpenVPN || profile.Path == "" {
		return errors.New("invalid OpenVPN profile")
	}
	a.mu.Lock()
	if a.current.ID != "" {
		a.mu.Unlock()
		return errors.New("an OpenVPN profile is already owned")
	}
	a.current = profile
	a.mu.Unlock()
	if err := a.backend.Activate(ctx, profile.Path, filepath.Dir(profile.Path)); err != nil {
		a.mu.Lock()
		if a.current.Path == profile.Path {
			a.current = Profile{}
		}
		a.mu.Unlock()
		return err
	}
	return nil
}

func (a *OpenVPNAdapter) Stop(ctx context.Context, profile Profile) error {
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	if current.ID != "" && current.ID != profile.ID {
		return errors.Join(ErrIdentityConflict, errors.New("refusing to stop a different OpenVPN profile"))
	}
	if err := a.backend.Deactivate(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.current = Profile{}
	a.mu.Unlock()
	return nil
}

func (a *OpenVPNAdapter) Status(context.Context, Profile) (ProtocolStatus, error) {
	state := a.backend.State()
	switch {
	case state.Running && state.Ready:
		return ProtocolStatus{State: "active"}, nil
	case state.Running:
		return ProtocolStatus{State: "starting"}, nil
	case state.UnexpectedExit || state.LastError != "":
		return ProtocolStatus{State: "failed"}, nil
	default:
		return ProtocolStatus{State: "inactive"}, nil
	}
}

func (a *OpenVPNAdapter) Shutdown(ctx context.Context) error {
	err := a.backend.Shutdown(ctx)
	if err == nil {
		a.mu.Lock()
		a.current = Profile{}
		a.mu.Unlock()
	}
	return err
}

func (a *OpenVPNAdapter) SetUnexpectedExitHandler(handler func(UnexpectedExit)) {
	a.mu.Lock()
	a.exitHandler = handler
	a.mu.Unlock()
}

func (a *OpenVPNAdapter) unexpectedExit(cleanupProved bool) {
	a.mu.Lock()
	profile := a.current
	a.current = Profile{}
	handler := a.exitHandler
	a.mu.Unlock()
	if handler != nil && profile.ID != "" {
		handler(UnexpectedExit{ProfileID: profile.ID, ExecutionPath: profile.Path, CleanupProved: cleanupProved})
	}
}
