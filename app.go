package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	maxRequestBody = 16 << 10
	maxPreferences = 100
	maxRecents     = 5
	commandTimeout = 30 * time.Second
	stateVersion   = 1
)

var ErrManagedStateConflict = errors.New("multiple Tunnelfolio-managed VPN profiles are active")

type Config struct {
	Version       int    `json:"version"`
	ActiveProfile string `json:"active_profile"`
	ConnectedAt   int64  `json:"connected_at,omitempty"`
}

type Preferences struct {
	Favorites    []string `json:"favorites"`
	Recents      []string `json:"recents"`
	TipDismissed bool     `json:"tip_dismissed"`
}

type Server struct {
	catalog  *ProfileCatalog
	backends map[string]managedBackend

	stateMu            sync.Mutex
	config             Config
	configPath         string
	prefs              Preferences
	prefsPath          string
	writeState         func(string, any) (stateWriteResult, error)
	lifecycle          string
	lifecycleProfile   *CatalogProfile
	lastLifecycleError string

	transitionGate chan struct{}
	trustedProxy   bool
	proxyToken     []byte
	readOnly       bool
}

func NewServer(opts options, catalog *ProfileCatalog, backends map[string]managedBackend) (*Server, error) {
	if catalog == nil {
		return nil, errors.New("profile catalog is required")
	}
	if err := ensurePrivateDir(opts.stateDir); err != nil {
		return nil, fmt.Errorf("prepare state directory: %w", err)
	}
	configPath, prefsPath := statePaths(opts.stateDir)
	server := &Server{
		catalog:        catalog,
		backends:       backends,
		configPath:     configPath,
		prefsPath:      prefsPath,
		writeState:     writeJSONAtomic,
		lifecycle:      "disconnected",
		transitionGate: make(chan struct{}, 1),
		trustedProxy:   opts.trustedProxy,
		readOnly:       opts.readOnly,
	}
	server.transitionGate <- struct{}{}
	if opts.trustedProxy {
		var err error
		server.proxyToken, err = loadProxyToken(opts.proxyTokenFile)
		if err != nil {
			return nil, fmt.Errorf("load proxy token: %w", err)
		}
	}
	if err := readJSON(configPath, &server.config); err != nil && !errors.Is(err, errNotExist) {
		return nil, fmt.Errorf("load connection state: %w", err)
	}
	if server.config.Version == 0 {
		server.config.Version = stateVersion
	}
	if server.config.Version != stateVersion {
		return nil, fmt.Errorf("unsupported state version %d", server.config.Version)
	}
	if server.config.ActiveProfile != "" {
		if _, err := catalog.Resolve(server.config.ActiveProfile); err != nil {
			return nil, fmt.Errorf("state active profile: %w", err)
		}
	}
	if err := readJSON(prefsPath, &server.prefs); err != nil && !errors.Is(err, errNotExist) {
		return nil, fmt.Errorf("load preferences: %w", err)
	}
	server.prefs.normalize()
	if err := server.validatePreferenceList(server.prefs.Favorites, maxPreferences); err != nil {
		return nil, fmt.Errorf("state favorites: %w", err)
	}
	if err := server.validatePreferenceList(server.prefs.Recents, maxRecents); err != nil {
		return nil, fmt.Errorf("state recents: %w", err)
	}
	return server, nil
}

func (p *Preferences) normalize() {
	if p.Favorites == nil {
		p.Favorites = []string{}
	}
	if p.Recents == nil {
		p.Recents = []string{}
	}
}

func (s *Server) mutation(operation string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		degraded := false
		defer func() {
			outcome := c.GetString("audit_outcome")
			if outcome == "" {
				outcome = fmt.Sprintf("http_%d", c.Writer.Status())
			}
			degraded = degraded || c.Writer.Status() >= http.StatusInternalServerError
			s.audit(c, operation, c.GetString("audit_profile"), outcome, degraded)
		}()
		if s.readOnly {
			writeError(c, http.StatusForbidden, "read_only", "mutations are disabled")
			return
		}
		if !s.trustedProxy {
			writeError(c, http.StatusUnauthorized, "proxy_auth_required", "authenticated proxy mode is required for mutations")
			return
		}
		if !validMutationOrigin(c, true) {
			writeError(c, http.StatusForbidden, "invalid_origin", "request origin is not allowed")
			return
		}
		handler(c)
	}
}

func (s *Server) acquireTransition() bool {
	select {
	case <-s.transitionGate:
		return true
	default:
		return false
	}
}

func (s *Server) releaseTransition() { s.transitionGate <- struct{}{} }

func (s *Server) handleHealth(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	availability := s.backendAvailability(ctx)
	ready := false
	for _, status := range availability {
		if status.Available {
			ready = true
			break
		}
	}
	readiness := "degraded"
	if ready {
		readiness = "ready"
	}
	c.JSON(http.StatusOK, gin.H{"live": true, "readiness": readiness, "read_only": s.readOnly, "backends": availability})
}

type backendAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func (s *Server) backendAvailability(ctx context.Context) map[string]backendAvailability {
	result := make(map[string]backendAvailability, len(s.backends))
	for _, kind := range []string{BackendOpenVPN, BackendWireGuard} {
		backend, ok := s.backends[kind]
		if !ok {
			result[kind] = backendAvailability{Reason: "backend is not configured"}
			continue
		}
		if err := backend.Availability(ctx); err != nil {
			result[kind] = backendAvailability{Reason: publicError(err)}
			continue
		}
		result[kind] = backendAvailability{Available: true}
	}
	return result
}

func (s *Server) observeAll(ctx context.Context) ([]CatalogProfile, error) {
	active := make([]CatalogProfile, 0, 2)
	for _, kind := range []string{BackendOpenVPN, BackendWireGuard} {
		backend, ok := s.backends[kind]
		if !ok {
			continue
		}
		if !backend.Enabled() {
			continue
		}
		if err := backend.Availability(ctx); err != nil {
			return nil, fmt.Errorf("observe %s backend availability: %w", kind, err)
		}
		profiles, err := backend.Observe(ctx)
		if err != nil {
			return nil, fmt.Errorf("observe %s backend: %w", kind, err)
		}
		active = append(active, profiles...)
	}
	return active, nil
}

func (s *Server) observe(ctx context.Context) (*CatalogProfile, error) {
	active, err := s.observeAll(ctx)
	if err != nil {
		return nil, err
	}
	if len(active) > 1 {
		return nil, ErrManagedStateConflict
	}
	if len(active) == 0 {
		return nil, nil
	}
	return &active[0], nil
}

func (s *Server) handleStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), commandTimeout)
	defer cancel()
	lifecycle, lifecycleProfile, lastLifecycleError := s.lifecycleSnapshot()
	if lifecycle == "connecting" || lifecycle == "switching" || lifecycle == "disconnecting" {
		response := gin.H{"connected": false, "lifecycle": lifecycle, "backends": s.backendAvailability(ctx)}
		if lifecycleProfile != nil {
			response["profile"] = lifecycleProfile
		}
		c.JSON(http.StatusOK, response)
		return
	}
	active, err := s.observe(ctx)
	if err != nil {
		if errors.Is(err, ErrManagedStateConflict) {
			s.setLifecycle("error_conflict", nil, "managed VPN state is conflicted")
			c.JSON(http.StatusConflict, gin.H{"connected": false, "lifecycle": "error_conflict", "error": "managed VPN state is conflicted", "backends": s.backendAvailability(ctx)})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"connected": false, "lifecycle": lifecycle, "error": "managed VPN state could not be observed", "backends": s.backendAvailability(ctx)})
		return
	}
	if lifecycle == "error_conflict" {
		c.JSON(http.StatusConflict, gin.H{"connected": false, "lifecycle": "error_conflict", "error": "managed VPN state must be explicitly cleaned up", "backends": s.backendAvailability(ctx)})
		return
	}
	response := gin.H{"connected": active != nil, "lifecycle": "disconnected", "backends": s.backendAvailability(ctx)}
	if active == nil {
		if diagnostic, ok := s.backends[BackendOpenVPN].(interface{ LastError() string }); ok {
			if lastError := diagnostic.LastError(); lastError != "" {
				response["last_error"] = lastError
			}
		}
		if lastLifecycleError != "" {
			response["last_error"] = lastLifecycleError
		}
		s.setLifecycle("disconnected", nil, lastLifecycleError)
		s.clearStaleConnectionState()
		c.JSON(http.StatusOK, response)
		return
	}
	response["lifecycle"] = "connected"
	s.setLifecycle("connected", active, lastLifecycleError)
	response["profile"] = active
	config := s.snapshotConfig()
	connectedAt := int64(0)
	if config.ActiveProfile == active.ID {
		connectedAt = config.ConnectedAt
	} else if config.ActiveProfile != "" || config.ConnectedAt != 0 {
		if _, err := s.persistConfig(Config{Version: stateVersion}); err != nil {
			log.Printf("mismatched connection state could not be cleared: %v", err)
		}
	}
	response["connected_since"] = connectedAt
	if connectedAt > 0 {
		response["duration_seconds"] = max(0, time.Now().Unix()-connectedAt)
	}
	if backend := s.backends[active.Backend]; backend != nil {
		if metrics, err := backend.Metrics(ctx, *active); err == nil && len(metrics) > 0 {
			response["metrics"] = metrics
		}
	}
	response["capabilities"] = profileCapabilities(active.Backend)
	c.JSON(http.StatusOK, response)
}

func (s *Server) lifecycleSnapshot() (string, *CatalogProfile, string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	var profile *CatalogProfile
	if s.lifecycleProfile != nil {
		copy := *s.lifecycleProfile
		profile = &copy
	}
	return s.lifecycle, profile, s.lastLifecycleError
}

func (s *Server) setLifecycle(lifecycle string, profile *CatalogProfile, lastError string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lifecycle = lifecycle
	s.lastLifecycleError = lastError
	if profile == nil {
		s.lifecycleProfile = nil
		return
	}
	copy := *profile
	s.lifecycleProfile = &copy
}

func (s *Server) clearStaleConnectionState() {
	s.stateMu.Lock()
	stale := s.config.ActiveProfile != "" || s.config.ConnectedAt != 0
	s.stateMu.Unlock()
	if stale {
		if _, err := s.persistConfig(Config{Version: stateVersion}); err != nil {
			log.Printf("stale connection state could not be cleared: %v", err)
		}
	}
}

type profileResponse struct {
	CatalogProfile
	Available    bool            `json:"available"`
	Capabilities map[string]bool `json:"capabilities"`
}

func (s *Server) handleProfiles(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), commandTimeout)
	defer cancel()
	availability := s.backendAvailability(ctx)
	profiles := make([]profileResponse, 0)
	for _, kind := range []string{BackendOpenVPN, BackendWireGuard} {
		entries, err := s.catalog.Profiles(kind)
		if err != nil {
			if errors.Is(err, ErrBackendUnavailable) {
				continue
			}
			log.Printf("profile listing failed backend=%s error=%v", kind, err)
			writeError(c, http.StatusInternalServerError, "profiles_unavailable", "profiles are unavailable")
			return
		}
		for _, profile := range entries {
			profiles = append(profiles, profileResponse{CatalogProfile: profile, Available: availability[kind].Available, Capabilities: profileCapabilities(kind)})
		}
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	c.JSON(http.StatusOK, profiles)
}

func (s *Server) handleConnect(c *gin.Context) {
	if !s.acquireTransition() {
		writeError(c, http.StatusConflict, "transition_in_progress", "another VPN transition is in progress")
		return
	}
	defer s.releaseTransition()
	if lifecycle, _, _ := s.lifecycleSnapshot(); lifecycle == "error_conflict" {
		writeError(c, http.StatusConflict, "managed_state_conflict", "managed VPN state must be cleaned up before switching")
		return
	}
	var request struct {
		Profile string `json:"profile"`
	}
	if err := bindBoundedJSON(c, &request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "request must contain one valid profile")
		return
	}
	target, err := s.catalog.Resolve(request.Profile)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_profile", "profile is not available")
		return
	}
	c.Set("audit_profile", target.ID)
	targetBackend := s.backends[target.Backend]
	ctx, cancel := context.WithTimeout(c.Request.Context(), commandTimeout)
	defer cancel()
	if targetBackend == nil || targetBackend.Availability(ctx) != nil {
		writeError(c, http.StatusServiceUnavailable, "backend_unavailable", "profile backend is unavailable")
		return
	}
	old, err := s.observe(ctx)
	if err != nil {
		if errors.Is(err, ErrManagedStateConflict) {
			s.setLifecycle("error_conflict", nil, "managed VPN state is conflicted")
			writeError(c, http.StatusConflict, "managed_state_conflict", "managed VPN state must be cleaned up before switching")
			return
		}
		writeError(c, http.StatusServiceUnavailable, "backend_observation_failed", "managed VPN state could not be observed")
		return
	}
	if old != nil && old.ID == target.ID {
		s.setLifecycle("connected", old, "")
		c.Set("audit_outcome", "already_connected")
		c.JSON(http.StatusOK, gin.H{"message": "Already connected", "profile": target.ID})
		return
	}
	transition := "connecting"
	if old != nil {
		transition = "switching"
	}
	s.setLifecycle(transition, &target, "")
	if old != nil {
		if err := s.backends[old.Backend].Stop(ctx, *old); err != nil {
			s.setLifecycle("error_conflict", old, "current profile could not be proven stopped")
			writeError(c, http.StatusBadGateway, "disconnect_failed", "current profile could not be proven stopped")
			return
		}
	}
	if err := targetBackend.Start(ctx, target); err != nil {
		s.handleFailedSwitch(c, old, target, "connect_failed", err)
		return
	}
	previous := s.snapshotConfig()
	next := Config{Version: stateVersion, ActiveProfile: target.ID, ConnectedAt: time.Now().Unix()}
	if _, err := s.persistConfig(next); err != nil {
		rollbackErr := s.compensate(target, old)
		if rollbackErr != nil {
			clearErr := s.clearConnectionClaim()
			if clearErr != nil {
				s.setLifecycle("error_conflict", nil, "network state and durable connection claim are uncertain")
				writeError(c, http.StatusInternalServerError, "state_clear_and_rollback_failed", "network restoration failed and the durable connection claim could not be proven cleared")
				return
			}
			s.setLifecycle("error_conflict", nil, "state save and network restoration failed")
			writeError(c, http.StatusInternalServerError, "state_save_and_rollback_failed", "state could not be saved and the previous network state could not be restored")
			return
		}
		if _, restoreErr := s.persistConfig(previous); restoreErr != nil {
			s.setLifecycle("error_conflict", old, "previous durable state could not be restored")
			writeError(c, http.StatusInternalServerError, "state_save_and_rollback_failed", "network state was restored but durable state could not be proven restored")
			return
		}
		if old != nil {
			s.setLifecycle("connected", old, "state could not be saved")
		} else {
			s.setLifecycle("disconnected", nil, "state could not be saved")
		}
		writeError(c, http.StatusInternalServerError, "state_save_failed", "state could not be saved; the previous profile was restored")
		return
	}
	s.recordRecent(target.ID)
	s.setLifecycle("connected", &target, "")
	c.Set("audit_outcome", "connected")
	c.JSON(http.StatusOK, gin.H{"message": "Connected", "profile": target.ID})
}

func (s *Server) handleFailedSwitch(c *gin.Context, old *CatalogProfile, target CatalogProfile, code string, _ error) {
	log.Printf("VPN transition failed target=%s class=%s", target.ID, code)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), commandTimeout)
	cleanupErr := s.backends[target.Backend].Stop(cleanupCtx, target)
	cleanupCancel()
	if cleanupErr != nil {
		if err := s.clearConnectionClaim(); err != nil {
			s.setLifecycle("error_conflict", nil, "failed target and durable connection claim are uncertain")
			writeError(c, http.StatusInternalServerError, "state_clear_and_connect_cleanup_failed", "the failed profile could not be proven stopped and the durable connection claim could not be proven cleared")
			return
		}
		s.setLifecycle("error_conflict", nil, "failed target could not be proven stopped")
		writeError(c, http.StatusBadGateway, "connect_cleanup_failed", "profile failed to connect and could not be proven stopped")
		return
	}
	if old == nil {
		if err := s.clearConnectionClaim(); err != nil {
			s.setLifecycle("error_conflict", nil, "disconnected state could not be saved")
			writeError(c, http.StatusInternalServerError, "state_clear_failed", "profile startup failed and disconnected state could not be proven saved")
			return
		}
		s.setLifecycle("disconnected", nil, "profile could not be connected")
		writeError(c, http.StatusBadGateway, code, "profile could not be connected")
		return
	}
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer restoreCancel()
	if err := s.backends[old.Backend].Start(restoreCtx, *old); err != nil {
		if clearErr := s.clearConnectionClaim(); clearErr != nil {
			log.Printf("VPN restoration and durable state cleanup failed old=%s", old.ID)
			s.setLifecycle("error_conflict", nil, "network state and durable connection claim are uncertain")
			writeError(c, http.StatusInternalServerError, "state_clear_and_rollback_failed", "the previous profile could not be restored and the durable connection claim could not be proven cleared")
			return
		}
		log.Printf("VPN restoration failed old=%s", old.ID)
		s.setLifecycle("error_conflict", nil, "new profile and restoration both failed")
		writeError(c, http.StatusBadGateway, "switch_and_rollback_failed", "new profile failed and the previous profile could not be restored")
		return
	}
	s.setLifecycle("connected", old, "requested profile failed; previous profile restored")
	writeError(c, http.StatusBadGateway, code, "profile could not be connected; the previous profile was restored")
}

func (s *Server) compensate(target CatalogProfile, old *CatalogProfile) error {
	stopCtx, stopCancel := context.WithTimeout(context.Background(), commandTimeout)
	stopErr := s.backends[target.Backend].Stop(stopCtx, target)
	stopCancel()
	if stopErr != nil {
		return stopErr
	}
	if old == nil {
		return nil
	}
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), commandTimeout)
	defer restoreCancel()
	return s.backends[old.Backend].Start(restoreCtx, *old)
}

func (s *Server) handleDisconnect(c *gin.Context) {
	if !s.acquireTransition() {
		writeError(c, http.StatusConflict, "transition_in_progress", "another VPN transition is in progress")
		return
	}
	defer s.releaseTransition()
	ctx, cancel := context.WithTimeout(c.Request.Context(), commandTimeout)
	defer cancel()
	activeProfiles, err := s.observeAll(ctx)
	if err != nil {
		writeError(c, http.StatusServiceUnavailable, "backend_observation_failed", "managed VPN state could not be observed")
		return
	}
	if len(activeProfiles) == 0 {
		if _, err := s.persistConfig(Config{Version: stateVersion}); err != nil {
			s.setLifecycle("error_conflict", nil, "disconnected state could not be saved")
			writeError(c, http.StatusInternalServerError, "state_save_failed", "disconnected state could not be saved")
			return
		}
		s.setLifecycle("disconnected", nil, "")
		c.Set("audit_outcome", "already_disconnected")
		c.JSON(http.StatusOK, gin.H{"message": "Already disconnected"})
		return
	}
	var lifecycleProfile *CatalogProfile
	if len(activeProfiles) == 1 {
		lifecycleProfile = &activeProfiles[0]
		c.Set("audit_profile", lifecycleProfile.ID)
	}
	s.setLifecycle("disconnecting", lifecycleProfile, "")
	for _, active := range activeProfiles {
		if err := s.backends[active.Backend].Stop(ctx, active); err != nil {
			s.setLifecycle("error_conflict", &active, "profile could not be proven stopped")
			writeError(c, http.StatusBadGateway, "disconnect_failed", "all managed profiles could not be proven stopped")
			return
		}
	}
	remaining, err := s.observeAll(ctx)
	if err != nil || len(remaining) != 0 {
		s.setLifecycle("error_conflict", nil, "managed profiles could not be proven absent")
		writeError(c, http.StatusBadGateway, "disconnect_failed", "all managed profiles could not be proven stopped")
		return
	}
	previous := s.snapshotConfig()
	if _, err := s.persistConfig(Config{Version: stateVersion}); err != nil {
		if len(activeProfiles) != 1 {
			if clearErr := s.clearConnectionClaim(); clearErr != nil {
				s.setLifecycle("error_conflict", nil, "durable connection claim could not be proven cleared after conflict cleanup")
				writeError(c, http.StatusInternalServerError, "state_clear_failed", "managed profiles were stopped but the durable connection claim could not be proven cleared")
				return
			}
			s.setLifecycle("disconnected", nil, "disconnected state required a recovery write")
			writeError(c, http.StatusInternalServerError, "state_save_failed", "managed profiles were stopped but disconnected state could not be saved")
			return
		}
		active := activeProfiles[0]
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cleanupCancel()
		if restoreErr := s.backends[active.Backend].Start(cleanupCtx, active); restoreErr != nil {
			if clearErr := s.clearConnectionClaim(); clearErr != nil {
				s.setLifecycle("error_conflict", nil, "network state and durable connection claim are uncertain")
				writeError(c, http.StatusInternalServerError, "state_clear_and_rollback_failed", "profile restoration failed and the durable connection claim could not be proven cleared")
				return
			}
			s.setLifecycle("error_conflict", nil, "state save and profile restoration failed")
			writeError(c, http.StatusInternalServerError, "state_save_and_rollback_failed", "state could not be saved and the profile could not be restored")
			return
		}
		if _, restoreErr := s.persistConfig(previous); restoreErr != nil {
			s.setLifecycle("error_conflict", &active, "network state was restored but durable state could not be proven restored")
			writeError(c, http.StatusInternalServerError, "state_save_and_rollback_failed", "profile was restored but durable state could not be proven restored")
			return
		}
		s.setLifecycle("connected", &active, "state could not be saved")
		writeError(c, http.StatusInternalServerError, "state_save_failed", "state could not be saved; the profile was restored")
		return
	}
	c.Set("audit_outcome", "disconnected")
	s.setLifecycle("disconnected", nil, "")
	c.JSON(http.StatusOK, gin.H{"message": "Disconnected"})
}

func (s *Server) snapshotConfig() Config {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.config
}

func (s *Server) persistConfig(config Config) (stateWriteResult, error) {
	result, err := s.writeState(s.configPath, config)
	if err != nil {
		return result, err
	}
	s.stateMu.Lock()
	s.config = config
	s.stateMu.Unlock()
	return result, nil
}

func (s *Server) clearConnectionClaim() error {
	if _, err := s.persistConfig(Config{Version: stateVersion}); err != nil {
		s.stateMu.Lock()
		s.config = Config{Version: stateVersion}
		s.stateMu.Unlock()
		return err
	}
	return nil
}

func (s *Server) recordRecent(profileID string) {
	s.stateMu.Lock()
	previous := s.prefs
	s.prefs.Recents = prependUnique(s.prefs.Recents, profileID, maxRecents)
	next := s.prefs
	adopt, err := s.writePreferences(previous, next)
	s.prefs = adopt
	if err != nil {
		log.Printf("recent profile save failed: %v", err)
	}
	s.stateMu.Unlock()
}

func (s *Server) handleGetPreferences(c *gin.Context) {
	s.stateMu.Lock()
	prefs := s.prefs
	s.stateMu.Unlock()
	c.JSON(http.StatusOK, prefs)
}

func (s *Server) handleSavePreferences(c *gin.Context) {
	var request Preferences
	if err := bindBoundedJSON(c, &request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_preferences", "preferences are invalid")
		return
	}
	request.normalize()
	if err := s.validatePreferenceList(request.Favorites, maxPreferences); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_favorites", err.Error())
		return
	}
	if err := s.validatePreferenceList(request.Recents, maxRecents); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_recents", err.Error())
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	previous := s.prefs
	adopt, err := s.writePreferences(previous, request)
	s.prefs = adopt
	if err != nil {
		writeError(c, http.StatusInternalServerError, "preferences_save_failed", "preferences could not be saved")
		return
	}
	c.Set("audit_outcome", "preferences_saved")
	c.JSON(http.StatusOK, request)
}

func (s *Server) writePreferences(previous, next Preferences) (Preferences, error) {
	result, err := s.writeState(s.prefsPath, next)
	if err == nil {
		return next, nil
	}
	if !result.Published {
		return previous, err
	}
	restored, restoreErr := s.writeState(s.prefsPath, previous)
	if restoreErr == nil || restored.Published {
		return previous, errors.Join(err, restoreErr)
	}
	return next, errors.Join(err, fmt.Errorf("restore previous preferences: %w", restoreErr))
}

func (s *Server) shutdown(ctx context.Context) error {
	var result error
	for _, backend := range s.backends {
		result = errors.Join(result, backend.Shutdown(ctx))
	}
	return result
}

func bindBoundedJSON(c *gin.Context, target any) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, maxRequestBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxRequestBody {
		return errors.New("request body is too large")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("request must be a JSON object")
	}
	if err := rejectDuplicateJSONKeys(trimmed); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func writeError(c *gin.Context, status int, code, message string) {
	c.Set("audit_outcome", code)
	c.JSON(status, gin.H{"error": message, "code": code})
}

func publicError(err error) string {
	if errors.Is(err, ErrBackendUnavailable) {
		return "backend is unavailable"
	}
	return "backend check failed"
}

func profileCapabilities(backend string) map[string]bool {
	return map[string]bool{"transfer_stats": backend == BackendWireGuard}
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

func (s *Server) validatePreferenceList(values []string, limit int) error {
	if len(values) > limit {
		return fmt.Errorf("at most %d profiles are allowed", limit)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return errors.New("duplicate profiles are not allowed")
		}
		if _, err := s.catalog.Resolve(value); err != nil {
			return errors.New("preferences contain an unavailable profile")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (s *Server) audit(c *gin.Context, operation, profileID, outcome string, degraded bool) {
	actor := ""
	if s.trustedProxy {
		actor = c.GetHeader("X-Remote-User")
	}
	s.auditActor(c, actor, operation, profileID, outcome, degraded)
}

func (s *Server) auditActor(c *gin.Context, actor, operation, profileID, outcome string, degraded bool) {
	log.Printf("audit request_id=%s actor=%q operation=%s profile=%q outcome=%s degraded=%t", c.GetString("request_id"), actor, operation, profileID, outcome, degraded)
}
