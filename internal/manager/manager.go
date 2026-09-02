package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
)

var (
	ErrTransitionInProgress = errors.New("a tunnel transition is already in progress")
	ErrManagedStateConflict = errors.New("multiple managed tunnels are active")
	ErrActiveProfile        = errors.New("active profiles cannot be removed")
	ErrTransitionFailed     = errors.New("tunnel transition failed")
)

type Availability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type ProfileView struct {
	ID                string          `json:"id"`
	Protocol          string          `json:"protocol"`
	DisplayName       string          `json:"display_name"`
	Group             string          `json:"group"`
	Location          string          `json:"location,omitempty"`
	Identifier        string          `json:"identifier"`
	OriginalFilename  string          `json:"original_filename"`
	ImportedAt        string          `json:"imported_at"`
	Favorite          bool            `json:"favorite"`
	Recent            bool            `json:"recent"`
	Available         bool            `json:"available"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
	Capabilities      map[string]bool `json:"capabilities"`
}

type Status struct {
	Lifecycle            string                  `json:"lifecycle"`
	Connected            bool                    `json:"connected"`
	Profile              *ProfileView            `json:"profile,omitempty"`
	ProtocolStatus       *tunnel.ProtocolStatus  `json:"protocol_status,omitempty"`
	Backends             map[string]Availability `json:"protocols"`
	LastError            string                  `json:"error,omitempty"`
	ObservedAt           time.Time               `json:"observed_at"`
	ObservationAvailable bool                    `json:"observation_available"`
	CanDisconnect        bool                    `json:"can_disconnect,omitempty"`
}

type ProfileDetail struct {
	ProfileView
	Current        bool                   `json:"current"`
	ProtocolStatus *tunnel.ProtocolStatus `json:"protocol_status,omitempty"`
}

type Preferences struct {
	Favorites   []string `json:"favorites"`
	Recents     []string `json:"recents"`
	StartupMode string   `json:"startup_mode"`
}

type RemoveResult struct {
	Profile        ProfileView
	CleanupPending bool
}

type Options struct {
	Store    *profiles.Store
	Backends map[string]tunnel.Backend
	ReadOnly bool
	Now      func() time.Time
	Timeout  time.Duration
}

type executionCopy struct {
	path    string
	cleanup func() error
}

type networkTruth uint8

const (
	networkTruthKnown networkTruth = iota
	networkTruthUncertain
)

type Manager struct {
	store    *profiles.Store
	backends map[string]tunnel.Backend
	readOnly bool
	now      func() time.Time
	timeout  time.Duration
	gate     chan struct{}

	executionMu sync.Mutex
	executions  map[string][]executionCopy

	stateMu          sync.RWMutex
	lifecycle        string
	lifecycleProfile string
	lastError        string
}

func New(options Options) (*Manager, error) {
	if options.Store == nil {
		return nil, errors.New("profile store is required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Timeout <= 0 {
		options.Timeout = tunnel.DefaultTimeout
	}
	manager := &Manager{
		store: options.Store, backends: make(map[string]tunnel.Backend, len(options.Backends)),
		readOnly: options.ReadOnly, now: options.Now, timeout: options.Timeout,
		gate: make(chan struct{}, 1), lifecycle: "disconnected", executions: make(map[string][]executionCopy),
	}
	for protocol, backend := range options.Backends {
		if backend == nil || backend.Protocol() != protocol {
			return nil, fmt.Errorf("invalid %s backend", protocol)
		}
		manager.backends[protocol] = backend
		if source, ok := backend.(tunnel.UnexpectedExitSource); ok {
			source.SetUnexpectedExitHandler(manager.handleUnexpectedExit)
		}
	}
	manager.gate <- struct{}{}
	return manager, nil
}

func (m *Manager) Store() *profiles.Store { return m.store }

func (m *Manager) AcquireLibraryOperation() (func(), error) {
	if !m.tryAcquire() {
		return nil, ErrTransitionInProgress
	}
	var once sync.Once
	return func() { once.Do(m.release) }, nil
}

func (m *Manager) Profiles(ctx context.Context) []ProfileView {
	manifest := m.store.Snapshot()
	availability := m.availability(ctx, manifest)
	result := make([]ProfileView, 0, len(manifest.Profiles))
	for _, profile := range profiles.SortedProfiles(manifest.Profiles) {
		result = append(result, view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly))
	}
	return result
}

func (m *Manager) Profile(ctx context.Context, id string) (ProfileView, error) {
	manifest := m.store.Snapshot()
	profile, found := manifest.Profile(id)
	if !found {
		return ProfileView{}, profiles.ErrNotFound
	}
	availability := m.availability(ctx, manifest)
	return view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly), nil
}

func (m *Manager) ProfileDetail(ctx context.Context, id string) (ProfileDetail, error) {
	profile, err := m.Profile(ctx, id)
	if err != nil {
		return ProfileDetail{}, err
	}
	result := ProfileDetail{ProfileView: profile}
	status := m.Status(ctx)
	if status.Profile != nil && status.Profile.ID == id {
		result.Current = status.Connected
		result.ProtocolStatus = status.ProtocolStatus
	}
	return result, nil
}

func (m *Manager) Preferences() Preferences {
	manifest := m.store.Snapshot()
	return Preferences{
		Favorites:   append([]string{}, manifest.Favorites...),
		Recents:     append([]string{}, manifest.Recents...),
		StartupMode: manifest.StartupMode,
	}
}

func (m *Manager) SetPreferences(favorites, recents []string, startupMode string) (Preferences, error) {
	if m.readOnly {
		return Preferences{}, profiles.ErrReadOnly
	}
	manifest, err := m.store.SetPreferences(favorites, recents, startupMode)
	if err != nil {
		return Preferences{}, err
	}
	return Preferences{
		Favorites:   append([]string{}, manifest.Favorites...),
		Recents:     append([]string{}, manifest.Recents...),
		StartupMode: manifest.StartupMode,
	}, nil
}

func (m *Manager) UpdateMetadata(ctx context.Context, id string, patch profiles.MetadataPatch) (ProfileView, error) {
	if m.readOnly {
		return ProfileView{}, profiles.ErrReadOnly
	}
	updated, err := m.store.UpdateMetadata(id, patch)
	if err != nil {
		return ProfileView{}, err
	}
	manifest := m.store.Snapshot()
	availability := m.availability(ctx, manifest)
	return view(updated, manifest, m.profileAvailability(updated, availability[updated.Protocol]), !m.readOnly), nil
}

func (m *Manager) Status(ctx context.Context) Status {
	lifecycle, transitionProfile, lastError := m.lifecycleSnapshot()
	manifest := m.store.Snapshot()
	availability := m.availability(ctx, manifest)
	if lifecycle == "state_conflict" {
		status := Status{
			Lifecycle: lifecycle, Backends: availability, LastError: lastError,
			ObservedAt: m.now().UTC(), CanDisconnect: !m.readOnly,
		}
		if profile, found := manifest.Profile(transitionProfile); found {
			profileView := view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly)
			status.Profile = &profileView
		}
		return status
	}
	if lifecycle == "starting" || lifecycle == "switching" || lifecycle == "disconnecting" || lifecycle == "restoring" {
		status := Status{
			Lifecycle: lifecycle, Backends: availability, LastError: lastError,
			ObservedAt: m.now().UTC(), ObservationAvailable: true,
		}
		if profile, found := manifest.Profile(transitionProfile); found {
			profileView := view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly)
			status.Profile = &profileView
		}
		return status
	}
	active, observationErr := m.observe(ctx, manifest)
	status := Status{
		Lifecycle: "disconnected", Backends: availability, ObservedAt: m.now().UTC(),
		ObservationAvailable: observationErr == nil,
	}
	if observationErr != nil {
		status.Lifecycle = "observation_unavailable"
		status.LastError = publicObservationError(observationErr)
		if errors.Is(observationErr, tunnel.ErrUnavailable) && len(active) == 1 {
			if profile, found := manifest.Profile(active[0].ProfileID); found {
				profileView := view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly)
				status.Connected = true
				status.Profile = &profileView
				if backend := m.backends[profile.Protocol]; backend != nil {
					if protocolStatus, err := backend.Status(ctx, runtimeProfile(m.store, profile)); err == nil {
						status.ProtocolStatus = &protocolStatus
					}
				}
			}
			return status
		}
		if errors.Is(observationErr, ErrManagedStateConflict) || errors.Is(observationErr, tunnel.ErrIdentityConflict) {
			status.Lifecycle = "state_conflict"
			status.CanDisconnect = errors.Is(observationErr, ErrManagedStateConflict) && !m.readOnly
		}
		return status
	}
	if len(active) == 0 {
		if lifecycle == "failed" {
			status.Lifecycle = lifecycle
			status.LastError = lastError
		}
		return status
	}
	profile, found := manifest.Profile(active[0].ProfileID)
	if !found {
		status.Lifecycle = "state_conflict"
		status.LastError = "An active tunnel no longer has a library record."
		return status
	}
	profileView := view(profile, manifest, m.profileAvailability(profile, availability[profile.Protocol]), !m.readOnly)
	if manifest.DesiredProfile != "" && manifest.DesiredProfile != profile.ID {
		status.Connected = true
		status.Lifecycle = "state_conflict"
		status.LastError = "The active tunnel differs from the desired profile."
		status.Profile = &profileView
		return status
	}
	status.Connected, status.Lifecycle, status.Profile = true, "active", &profileView
	backend := m.backends[profile.Protocol]
	if backend != nil {
		protocolStatus, err := backend.Status(ctx, runtimeProfile(m.store, profile))
		if err == nil {
			status.ProtocolStatus = &protocolStatus
		} else {
			status.ProtocolStatus = &tunnel.ProtocolStatus{State: "observation_unavailable"}
			status.LastError = "Protocol status could not be observed."
		}
	}
	return status
}

func (m *Manager) Connect(ctx context.Context, id string) error {
	if m.readOnly {
		return profiles.ErrReadOnly
	}
	if !m.tryAcquire() {
		return ErrTransitionInProgress
	}
	defer m.release()
	if lifecycle, _, _ := m.lifecycleSnapshot(); lifecycle == "state_conflict" {
		return ErrManagedStateConflict
	}
	manifest := m.store.Snapshot()
	target, found := manifest.Profile(id)
	if !found {
		return profiles.ErrNotFound
	}
	if _, err := m.store.Resolve(id); err != nil {
		m.setFailure(networkTruthKnown, id, "The requested profile is unavailable.", "The requested profile could not be validated safely.")
		return err
	}
	backend := m.backends[target.Protocol]
	if backend == nil {
		return tunnel.ErrUnavailable
	}
	availabilityCtx, cancel := context.WithTimeout(ctx, m.timeout)
	availabilityErr := backend.Available(availabilityCtx)
	cancel()
	if availabilityErr != nil {
		return tunnel.ErrUnavailable
	}
	active, err := m.observe(ctx, manifest)
	if err != nil {
		m.setFailure(networkTruthUncertain, id, "", "Tunnel state could not be proved before connecting.")
		return errors.Join(ErrManagedStateConflict, err)
	}
	if len(active) == 1 && active[0].ProfileID == id {
		if _, err := m.store.SetConnection(id, m.now().Unix(), true); err != nil {
			if reconcileErr := m.reconcileConnection(id, m.now().Unix()); reconcileErr != nil {
				m.setFailure(networkTruthUncertain, id, "", "The active tunnel could not be recorded durably.")
				return errors.Join(ErrManagedStateConflict, err, reconcileErr)
			}
		}
		m.setLifecycle("active", id, "")
		return nil
	}
	state := "starting"
	if len(active) == 1 {
		state = "switching"
	}
	m.setLifecycle(state, id, "")
	defer func() {
		lifecycle, _, _ := m.lifecycleSnapshot()
		if lifecycle == "starting" || lifecycle == "switching" {
			m.setLifecycle("failed", id, "Tunnel transition did not settle.")
		}
	}()
	var previous *profiles.Profile
	if len(active) == 1 {
		profile, exists := manifest.Profile(active[0].ProfileID)
		if !exists {
			m.setFailure(networkTruthUncertain, id, "", "The active tunnel no longer has a trusted library record.")
			return ErrManagedStateConflict
		}
		previous = &profile
		if err := m.stop(ctx, profile); err != nil {
			m.setFailure(networkTruthUncertain, profile.ID, "", "The active tunnel could not be proved stopped.")
			return errors.Join(ErrManagedStateConflict, ErrTransitionFailed, err)
		}
	}
	if err := m.start(ctx, target); err != nil {
		if errors.Is(err, tunnel.ErrCleanupUnproved) {
			reconcileErr := m.reconcileConnection(manifest.DesiredProfile, 0)
			m.setFailure(networkTruthUncertain, target.ID, "", "The failed tunnel could not be proved absent.")
			return errors.Join(ErrManagedStateConflict, err, reconcileErr)
		}
		if previous != nil {
			if restoreErr := m.start(context.Background(), *previous); restoreErr != nil {
				reconcileErr := m.reconcileConnection(previous.ID, 0)
				m.setFailure(networkTruthUncertain, target.ID, "", "The new tunnel failed and the previous tunnel could not be restored safely.")
				return errors.Join(ErrManagedStateConflict, ErrTransitionFailed, err, restoreErr, reconcileErr)
			}
			m.setLifecycle("active", previous.ID, "The new tunnel failed; the previous tunnel was restored.")
		} else {
			m.setLifecycle("failed", target.ID, "The tunnel could not be started.")
		}
		return errors.Join(ErrTransitionFailed, err)
	}
	if _, err := m.store.SetConnection(target.ID, m.now().Unix(), true); err != nil {
		return m.recoverPersistenceFailure(target, previous, err)
	}
	m.setLifecycle("active", target.ID, "")
	return nil
}

func (m *Manager) Disconnect(ctx context.Context) error {
	if m.readOnly {
		return profiles.ErrReadOnly
	}
	if !m.tryAcquire() {
		return ErrTransitionInProgress
	}
	defer m.release()
	priorLifecycle, _, _ := m.lifecycleSnapshot()
	m.setLifecycle("disconnecting", "", "")
	manifest := m.store.Snapshot()
	active, err := m.observe(ctx, manifest)
	if err != nil && !errors.Is(err, ErrManagedStateConflict) && priorLifecycle == "state_conflict" {
		recoveryCtx, cancel := context.WithTimeout(ctx, m.timeout)
		shutdownErr := m.shutdownBackends(recoveryCtx)
		active, err = m.observe(recoveryCtx, manifest)
		cancel()
		if err != nil {
			err = errors.Join(shutdownErr, err)
		}
	}
	if err != nil && !errors.Is(err, ErrManagedStateConflict) {
		m.setFailure(networkTruthUncertain, "", "", "Tunnel absence could not be proved before disconnecting.")
		return errors.Join(ErrManagedStateConflict, err)
	}
	var stopErr error
	for _, observation := range active {
		profile, found := manifest.Profile(observation.ProfileID)
		if !found {
			stopErr = errors.Join(stopErr, ErrManagedStateConflict)
			continue
		}
		stopErr = errors.Join(stopErr, m.stop(ctx, profile))
	}
	if stopErr != nil {
		m.setFailure(networkTruthUncertain, "", "", "One or more managed tunnels could not be proved stopped.")
		return errors.Join(ErrManagedStateConflict, ErrTransitionFailed, stopErr)
	}
	if cleanupErr := m.cleanupAllExecutions(); cleanupErr != nil {
		m.setFailure(networkTruthUncertain, "", "", "One or more private execution copies could not be cleaned safely.")
		return errors.Join(ErrManagedStateConflict, cleanupErr)
	}
	if _, err := m.store.SetConnection("", 0, false); err != nil {
		if repairErr := m.store.RepairDurability(); repairErr != nil {
			m.setFailure(networkTruthUncertain, "", "", "The tunnel stopped, but desired-state durability is unknown.")
			return errors.Join(ErrManagedStateConflict, err, repairErr)
		}
		if _, retryErr := m.store.SetConnection("", 0, false); retryErr != nil {
			m.setFailure(networkTruthUncertain, "", "", "The tunnel stopped, but desired state could not be cleared safely.")
			return errors.Join(ErrManagedStateConflict, err, retryErr)
		}
	}
	m.setLifecycle("disconnected", "", "")
	return nil
}

func (m *Manager) Remove(ctx context.Context, id string) (RemoveResult, error) {
	if m.readOnly {
		return RemoveResult{}, profiles.ErrReadOnly
	}
	if !m.tryAcquire() {
		return RemoveResult{}, ErrTransitionInProgress
	}
	defer m.release()
	if lifecycle, _, _ := m.lifecycleSnapshot(); lifecycle == "state_conflict" {
		return RemoveResult{}, ErrManagedStateConflict
	}
	manifest := m.store.Snapshot()
	profile, found := manifest.Profile(id)
	if !found {
		return RemoveResult{}, profiles.ErrNotFound
	}
	active, err := m.observeProtocol(ctx, manifest, profile.Protocol)
	if err != nil {
		return RemoveResult{}, err
	}
	for _, observation := range active {
		if observation.ProfileID == id {
			return RemoveResult{}, ErrActiveProfile
		}
	}
	removed, err := m.store.Remove(id)
	if err != nil {
		return RemoveResult{}, err
	}
	return RemoveResult{Profile: view(profile, manifest, m.profileAvailability(profile, Availability{Available: m.backends[profile.Protocol] != nil}), !m.readOnly), CleanupPending: removed.CleanupPending}, nil
}

func (m *Manager) ReconcileStartup(ctx context.Context) {
	<-m.gate
	defer m.release()
	m.setLifecycle("restoring", "", "")
	manifest := m.store.Snapshot()
	active, err := m.observe(ctx, manifest)
	if err != nil {
		m.setFailure(networkTruthUncertain, "", "", "Managed tunnel absence could not be proved during startup.")
		return
	}
	if len(active) == 1 {
		if active[0].ProfileID == manifest.DesiredProfile {
			m.setLifecycle("active", active[0].ProfileID, "")
		} else {
			m.setLifecycle("state_conflict", active[0].ProfileID, "The active tunnel differs from the desired profile.")
		}
		return
	}
	if !m.readOnly && manifest.ConnectedAt != 0 {
		if err := m.reconcileConnection(manifest.DesiredProfile, 0); err != nil {
			m.setFailure(networkTruthUncertain, manifest.DesiredProfile, "", "Disconnected startup state could not be recorded durably.")
			return
		}
		manifest = m.store.Snapshot()
	}
	if m.readOnly || manifest.StartupMode == profiles.StartupManual || manifest.DesiredProfile == "" {
		m.setLifecycle("disconnected", "", "")
		return
	}
	target, found := manifest.Profile(manifest.DesiredProfile)
	if !found || m.backends[target.Protocol] == nil {
		m.setFailure(networkTruthKnown, manifest.DesiredProfile, "The desired profile is unavailable.", "")
		return
	}
	if _, err := m.store.Resolve(target.ID); err != nil {
		m.setFailure(networkTruthKnown, manifest.DesiredProfile, "The desired profile could not be restored.", "")
		return
	}
	m.setLifecycle("restoring", target.ID, "")
	if err := m.start(ctx, target); err != nil {
		truth := networkTruthKnown
		if errors.Is(err, tunnel.ErrCleanupUnproved) {
			truth = networkTruthUncertain
		}
		m.setFailure(truth, target.ID, "The desired profile could not be restored.", "The failed startup restoration could not be proved absent.")
		return
	}
	if _, err := m.store.SetConnection(target.ID, m.now().Unix(), true); err != nil {
		stopErr := m.stop(context.Background(), target)
		repairErr := m.store.RepairDurability()
		var reconcileErr error
		if stopErr == nil && repairErr == nil {
			reconcileErr = m.reconcileConnection(target.ID, 0)
		}
		truth := recoveryTruth(stopErr, nil, repairErr, reconcileErr)
		m.setFailure(truth, target.ID, "The restored tunnel could not be recorded durably.", "Startup restoration could not be compensated safely.")
		return
	}
	m.setLifecycle("active", target.ID, "")
}

func (m *Manager) Shutdown(ctx context.Context) error {
	result := m.shutdownBackends(ctx)
	result = errors.Join(result, m.cleanupAllExecutions())
	return result
}

func (m *Manager) shutdownBackends(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	var result error
	for _, backend := range m.backends {
		result = errors.Join(result, backend.Shutdown(operationCtx))
	}
	return result
}

func (m *Manager) observe(ctx context.Context, manifest profiles.Manifest) ([]tunnel.Observation, error) {
	active := make([]tunnel.Observation, 0, 2)
	missingBackend := false
	for _, protocol := range []string{profiles.ProtocolOpenVPN, profiles.ProtocolWireGuard} {
		observed, err := m.observeProtocol(ctx, manifest, protocol)
		if errors.Is(err, tunnel.ErrUnavailable) {
			missingBackend = true
			continue
		}
		if err != nil {
			return active, err
		}
		active = append(active, observed...)
	}
	if len(active) > 1 {
		return active, ErrManagedStateConflict
	}
	if missingBackend {
		return active, tunnel.ErrUnavailable
	}
	return active, nil
}

func (m *Manager) observeProtocol(ctx context.Context, manifest profiles.Manifest, protocol string) ([]tunnel.Observation, error) {
	profilesForProtocol := make([]tunnel.Profile, 0)
	for _, profile := range manifest.Profiles {
		if profile.Protocol == protocol {
			profilesForProtocol = append(profilesForProtocol, runtimeProfile(m.store, profile))
		}
	}
	if len(profilesForProtocol) == 0 {
		return nil, nil
	}
	backend := m.backends[protocol]
	if backend == nil {
		return nil, tunnel.ErrUnavailable
	}
	return backend.Observe(ctx, profilesForProtocol)
}

func (m *Manager) availability(ctx context.Context, manifest profiles.Manifest) map[string]Availability {
	result := make(map[string]Availability, 2)
	for _, protocol := range []string{profiles.ProtocolOpenVPN, profiles.ProtocolWireGuard} {
		backend := m.backends[protocol]
		if backend == nil {
			result[protocol] = Availability{Reason: "Protocol tooling is not installed."}
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := backend.Available(checkCtx)
		cancel()
		if err != nil {
			result[protocol] = Availability{Reason: "Protocol tooling is unavailable."}
			continue
		}
		result[protocol] = Availability{Available: true}
	}
	_ = manifest
	return result
}

func (m *Manager) profileAvailability(profile profiles.Profile, backend Availability) Availability {
	if _, err := m.store.Resolve(profile.ID); err != nil {
		return Availability{Reason: "Profile data is unavailable."}
	}
	return backend
}

func (m *Manager) start(ctx context.Context, profile profiles.Profile) error {
	backend := m.backends[profile.Protocol]
	if backend == nil {
		return tunnel.ErrUnavailable
	}
	operationCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	verified, path, cleanup, err := m.store.PrepareExecution(profile.ID)
	if err != nil {
		return err
	}
	if err := backend.Start(operationCtx, runtimeProfileAt(verified, path)); err != nil {
		cleanupErr := cleanup()
		if cleanupErr != nil {
			m.addExecution(profile.ID, executionCopy{path: path, cleanup: cleanup})
			return errors.Join(err, tunnel.ErrCleanupUnproved, cleanupErr)
		}
		return err
	}
	m.addExecution(profile.ID, executionCopy{path: path, cleanup: cleanup})
	return nil
}

func (m *Manager) stop(ctx context.Context, profile profiles.Profile) error {
	backend := m.backends[profile.Protocol]
	if backend == nil {
		return tunnel.ErrUnavailable
	}
	operationCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	verified, path, cleanup, err := m.store.PrepareExecution(profile.ID)
	if err != nil {
		return err
	}
	stopErr := backend.Stop(operationCtx, runtimeProfileAt(verified, path))
	cleanupErr := cleanup()
	if cleanupErr != nil {
		m.addExecution(profile.ID, executionCopy{path: path, cleanup: cleanup})
	}
	if stopErr == nil {
		cleanupErr = errors.Join(cleanupErr, m.cleanupExecutions(profile.ID, path))
	}
	return errors.Join(stopErr, cleanupErr)
}

func (m *Manager) recoverPersistenceFailure(target profiles.Profile, previous *profiles.Profile, cause error) error {
	cleanupErr := m.stop(context.Background(), target)
	var restoreErr error
	actual := ""
	if previous != nil && cleanupErr == nil {
		restoreErr = m.start(context.Background(), *previous)
		if restoreErr == nil {
			actual = previous.ID
		}
	}
	repairErr := m.store.RepairDurability()
	var reconcileErr error
	if cleanupErr == nil && repairErr == nil {
		desired := actual
		if previous != nil && restoreErr != nil {
			desired = previous.ID
		}
		_, reconcileErr = m.store.SetConnection(desired, func() int64 {
			if actual != "" {
				return m.now().Unix()
			}
			return 0
		}(), false)
	}
	truth := recoveryTruth(cleanupErr, restoreErr, repairErr, reconcileErr)
	if truth == networkTruthKnown && actual != "" {
		m.setLifecycle("active", actual, "The network transition could not be recorded durably; the previous tunnel was restored.")
	} else {
		m.setFailure(truth, target.ID, "The network transition could not be recorded durably and was rolled back.", "The network transition could not be compensated safely.")
	}
	result := errors.Join(cause, cleanupErr, restoreErr, repairErr, reconcileErr)
	if truth == networkTruthUncertain {
		result = errors.Join(ErrManagedStateConflict, result)
	}
	return result
}

func recoveryTruth(cleanupErr, restoreErr, repairErr, reconcileErr error) networkTruth {
	if cleanupErr != nil || restoreErr != nil || repairErr != nil || reconcileErr != nil {
		return networkTruthUncertain
	}
	return networkTruthKnown
}

func lifecycleForTruth(truth networkTruth) string {
	if truth == networkTruthUncertain {
		return "state_conflict"
	}
	return "failed"
}

func (m *Manager) setFailure(truth networkTruth, profile, failedMessage, conflictMessage string) {
	message := failedMessage
	if truth == networkTruthUncertain {
		message = conflictMessage
	}
	m.setLifecycle(lifecycleForTruth(truth), profile, message)
}

func (m *Manager) reconcileConnection(desired string, connectedAt int64) error {
	_, firstErr := m.store.SetConnection(desired, connectedAt, false)
	if firstErr == nil {
		return nil
	}
	if err := m.store.RepairDurability(); err != nil {
		return errors.Join(firstErr, err)
	}
	if _, err := m.store.SetConnection(desired, connectedAt, false); err != nil {
		return errors.Join(firstErr, err)
	}
	return nil
}

func (m *Manager) addExecution(profileID string, execution executionCopy) {
	m.executionMu.Lock()
	m.executions[profileID] = append(m.executions[profileID], execution)
	m.executionMu.Unlock()
}

func (m *Manager) takeExecutions(profileID, exceptPath string) []executionCopy {
	m.executionMu.Lock()
	defer m.executionMu.Unlock()
	current := m.executions[profileID]
	taken := make([]executionCopy, 0, len(current))
	kept := make([]executionCopy, 0, len(current))
	for _, execution := range current {
		if exceptPath != "" && execution.path == exceptPath {
			kept = append(kept, execution)
			continue
		}
		taken = append(taken, execution)
	}
	if len(kept) == 0 {
		delete(m.executions, profileID)
	} else {
		m.executions[profileID] = kept
	}
	return taken
}

func (m *Manager) cleanupExecutions(profileID, exceptPath string) error {
	executions := m.takeExecutions(profileID, exceptPath)
	var result error
	for _, execution := range executions {
		if err := execution.cleanup(); err != nil {
			result = errors.Join(result, err)
			m.addExecution(profileID, execution)
		}
	}
	return result
}

func (m *Manager) cleanupExecutionPath(profileID, path string) error {
	if path == "" {
		return errors.New("execution path is required")
	}
	m.executionMu.Lock()
	current := m.executions[profileID]
	var target *executionCopy
	kept := make([]executionCopy, 0, len(current))
	for index := range current {
		if target == nil && current[index].path == path {
			copy := current[index]
			target = &copy
			continue
		}
		kept = append(kept, current[index])
	}
	if len(kept) == 0 {
		delete(m.executions, profileID)
	} else {
		m.executions[profileID] = kept
	}
	m.executionMu.Unlock()
	if target == nil {
		return nil
	}
	if err := target.cleanup(); err != nil {
		m.addExecution(profileID, *target)
		return err
	}
	return nil
}

func (m *Manager) cleanupAllExecutions() error {
	m.executionMu.Lock()
	profileIDs := make([]string, 0, len(m.executions))
	for profileID := range m.executions {
		profileIDs = append(profileIDs, profileID)
	}
	m.executionMu.Unlock()
	var result error
	for _, profileID := range profileIDs {
		result = errors.Join(result, m.cleanupExecutions(profileID, ""))
	}
	return result
}

func (m *Manager) handleUnexpectedExit(event tunnel.UnexpectedExit) {
	<-m.gate
	defer m.release()
	cleanupErr := m.cleanupExecutionPath(event.ProfileID, event.ExecutionPath)
	if !event.CleanupProved || cleanupErr != nil {
		m.setFailure(networkTruthUncertain, event.ProfileID, "", "The OpenVPN process exited and cleanup could not be proved.")
		return
	}
	manifest := m.store.Snapshot()
	if manifest.DesiredProfile != event.ProfileID {
		if err := m.cleanupExecutions(event.ProfileID, ""); err != nil {
			m.setFailure(networkTruthUncertain, event.ProfileID, "", "Private OpenVPN execution copies could not be cleaned safely.")
		}
		return
	}
	observationCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
	active, observationErr := m.observe(observationCtx, manifest)
	cancel()
	if observationErr != nil {
		m.setFailure(networkTruthUncertain, event.ProfileID, "", "Tunnel state could not be proved after the OpenVPN process exited.")
		return
	}
	if len(active) != 0 {
		if len(active) == 1 && active[0].ProfileID == event.ProfileID {
			return
		}
		m.setFailure(networkTruthUncertain, event.ProfileID, "", "A different tunnel was observed after the OpenVPN process exited.")
		return
	}
	if err := m.cleanupExecutions(event.ProfileID, ""); err != nil {
		m.setFailure(networkTruthUncertain, event.ProfileID, "", "Private OpenVPN execution copies could not be cleaned safely.")
		return
	}
	if manifest.ConnectedAt != 0 {
		if err := m.reconcileConnection(event.ProfileID, 0); err != nil {
			m.setFailure(networkTruthUncertain, event.ProfileID, "", "The OpenVPN exit could not be recorded durably.")
			return
		}
	}
	m.setFailure(networkTruthKnown, event.ProfileID, "The OpenVPN process exited unexpectedly.", "")
}

func runtimeProfile(store *profiles.Store, profile profiles.Profile) tunnel.Profile {
	return runtimeProfileAt(profile, store.ObjectPath(profile))
}

func runtimeProfileAt(profile profiles.Profile, path string) tunnel.Profile {
	return tunnel.Profile{
		ID: profile.ID, Protocol: profile.Protocol, Identifier: profile.Identifier,
		Path: path, WireGuardPublicKeySHA256: profile.WireGuardPublicKeySHA256,
	}
}

func view(profile profiles.Profile, manifest profiles.Manifest, availability Availability, mutable bool) ProfileView {
	return ProfileView{
		ID: profile.ID, Protocol: profile.Protocol, DisplayName: profile.DisplayName, Group: profile.Group,
		Location: profile.Location, Identifier: profile.Identifier, OriginalFilename: profile.OriginalFilename,
		ImportedAt: profile.ImportedAt.UTC().Format(time.RFC3339), Favorite: contains(manifest.Favorites, profile.ID),
		Recent: contains(manifest.Recents, profile.ID), Available: availability.Available,
		UnavailableReason: availability.Reason,
		Capabilities: map[string]bool{
			"connect": mutable && availability.Available, "favorite": mutable,
			"edit_metadata": mutable, "remove": mutable,
		},
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (m *Manager) tryAcquire() bool {
	select {
	case <-m.gate:
		return true
	default:
		return false
	}
}

func (m *Manager) release() { m.gate <- struct{}{} }

func (m *Manager) setLifecycle(state, profile, message string) {
	m.stateMu.Lock()
	m.lifecycle, m.lifecycleProfile, m.lastError = state, profile, message
	m.stateMu.Unlock()
}

func (m *Manager) lifecycleSnapshot() (string, string, string) {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.lifecycle, m.lifecycleProfile, m.lastError
}

func publicObservationError(err error) string {
	if errors.Is(err, ErrManagedStateConflict) || errors.Is(err, tunnel.ErrIdentityConflict) {
		return "Managed tunnel state is conflicted."
	}
	return "Tunnel state could not be observed."
}
