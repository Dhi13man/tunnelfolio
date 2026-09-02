package httpapi

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Dhi13man/tunnelfolio/internal/manager"
	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
	"github.com/Dhi13man/tunnelfolio/internal/web"
)

type Options struct {
	Manager      *manager.Manager
	Imports      *profiles.ImportService
	RuntimeDir   string
	TrustedProxy bool
	ProxyToken   []byte
	ReadOnly     bool
	Logger       *log.Logger
}

type Server struct {
	manager      *manager.Manager
	imports      *profiles.ImportService
	runtimeDir   string
	trustedProxy bool
	readOnly     bool
	logger       *log.Logger
	importGate   chan struct{}
}

func New(options Options) (http.Handler, error) {
	if options.Manager == nil {
		return nil, errors.New("manager is required")
	}
	if options.RuntimeDir == "" {
		return nil, errors.New("runtime directory is required")
	}
	if options.TrustedProxy && len(options.ProxyToken) == 0 {
		return nil, errors.New("trusted proxy token is required")
	}
	if !options.ReadOnly && options.Imports == nil {
		return nil, errors.New("import service is required in mutable mode")
	}
	if options.Logger == nil {
		options.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	server := &Server{
		manager: options.Manager, imports: options.Imports, runtimeDir: options.RuntimeDir,
		trustedProxy: options.TrustedProxy, readOnly: options.ReadOnly, logger: options.Logger,
		importGate: make(chan struct{}, 1),
	}
	server.importGate <- struct{}{}
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	_ = router.SetTrustedProxies(nil)
	router.Use(gin.Recovery(), requestContext(), requestLogger(server.logger), securityHeaders())
	if options.TrustedProxy {
		router.Use(requireTrustedProxy(options.ProxyToken))
	}
	router.GET("/", server.index)
	router.GET("/assets/:name", server.asset)
	router.GET("/healthz", server.health)
	router.GET("/api/status", server.status)
	router.GET("/api/profiles", server.listProfiles)
	router.GET("/api/profiles/:id", server.getProfile)
	router.GET("/api/preferences", server.getPreferences)
	router.POST("/api/connect", server.mutation("connect", server.connect))
	router.POST("/api/disconnect", server.mutation("disconnect", server.disconnect))
	router.PUT("/api/preferences", server.mutation("preferences", server.putPreferences))
	router.POST("/api/imports/inspect", server.mutation("inspect", server.inspectImport))
	router.POST("/api/profiles/import", server.mutation("import", server.commitImport))
	router.PATCH("/api/profiles/:id", server.mutation("metadata", server.patchProfile))
	router.DELETE("/api/profiles/:id", server.mutation("remove", server.removeProfile))
	return router, nil
}

func (s *Server) mutation(operation string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.readOnly {
			writeError(c, http.StatusForbidden, "read_only", "Mutations are disabled.")
			return
		}
		if !s.trustedProxy {
			writeError(c, http.StatusUnauthorized, "proxy_auth_required", "Authenticated proxy mode is required for mutations.")
			return
		}
		if !validMutationOrigin(c, true) {
			writeError(c, http.StatusForbidden, "invalid_origin", "The request origin is not allowed.")
			return
		}
		c.Set("audit_operation", operation)
		handler(c)
		s.logger.Printf("audit request_id=%s actor=%q operation=%s subject=%q outcome=%s", c.GetString("request_id"), c.GetHeader("X-Remote-User"), operation, c.GetString("audit_subject"), c.GetString("audit_outcome"))
	}
}

func (s *Server) index(c *gin.Context) {
	data, err := web.Index()
	if err != nil {
		writeError(c, http.StatusInternalServerError, "asset_unavailable", "The application interface is unavailable.")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

func (s *Server) asset(c *gin.Context) {
	data, contentType, err := web.Asset(c.Param("name"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, contentType, data)
}

func (s *Server) health(c *gin.Context) {
	status := s.manager.Status(c.Request.Context())
	readiness := "degraded"
	for _, protocol := range status.Backends {
		if protocol.Available {
			readiness = "ready"
			break
		}
	}
	c.JSON(http.StatusOK, gin.H{"live": true, "readiness": readiness, "read_only": s.readOnly, "protocols": status.Backends})
}

func (s *Server) status(c *gin.Context) {
	status := s.manager.Status(c.Request.Context())
	switch status.Lifecycle {
	case "state_conflict":
		c.JSON(http.StatusConflict, struct {
			manager.Status
			Code string `json:"code"`
		}{Status: status, Code: "managed_state_conflict"})
	case "observation_unavailable":
		c.JSON(http.StatusServiceUnavailable, struct {
			manager.Status
			Code string `json:"code"`
		}{Status: status, Code: "observation_unavailable"})
	default:
		c.JSON(http.StatusOK, status)
	}
}

func (s *Server) listProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, s.manager.Profiles(c.Request.Context()))
}

func (s *Server) getProfile(c *gin.Context) {
	profile, err := s.manager.ProfileDetail(c.Request.Context(), c.Param("id"))
	if err != nil {
		writeMappedError(c, err)
		return
	}
	c.JSON(http.StatusOK, profile)
}

func (s *Server) connect(c *gin.Context) {
	var request struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSONRequest(c.Request, &request); err != nil {
		writeJSONEnvelopeError(c, err)
		return
	}
	if request.Profile == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "The request must name one profile.")
		return
	}
	c.Set("audit_subject", request.Profile)
	if err := s.manager.Connect(c.Request.Context(), request.Profile); err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "connected")
	c.JSON(http.StatusOK, gin.H{"profile": request.Profile, "result": "connected"})
}

func (s *Server) disconnect(c *gin.Context) {
	if !requestBodyEmpty(c.Request) {
		writeError(c, http.StatusBadRequest, "invalid_request", "Disconnect does not accept a request body.")
		return
	}
	if err := s.manager.Disconnect(c.Request.Context()); err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "disconnected")
	c.JSON(http.StatusOK, gin.H{"result": "disconnected"})
}

func (s *Server) getPreferences(c *gin.Context) { c.JSON(http.StatusOK, s.manager.Preferences()) }

func (s *Server) putPreferences(c *gin.Context) {
	var request struct {
		Favorites   []string `json:"favorites"`
		Recents     []string `json:"recents"`
		StartupMode string   `json:"startup_mode"`
	}
	if err := decodeJSONRequest(c.Request, &request); err != nil {
		writeJSONEnvelopeError(c, err)
		return
	}
	if request.Favorites == nil || request.Recents == nil {
		writeError(c, http.StatusBadRequest, "invalid_preferences", "Preferences must provide favorites, recents, and startup mode.")
		return
	}
	preferences, err := s.manager.SetPreferences(request.Favorites, request.Recents, request.StartupMode)
	if err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "saved")
	c.JSON(http.StatusOK, preferences)
}

func (s *Server) inspectImport(c *gin.Context) {
	if !s.acquireImport() {
		writeError(c, http.StatusConflict, "import_busy", "Another import is in progress.")
		return
	}
	defer s.releaseImport()
	setImportReadDeadline(c)
	staged, err := stageImportMultipart(c, s.runtimeDir, map[string]bool{"protocol_overrides": true})
	if err != nil {
		writeImportEnvelopeError(c, err)
		return
	}
	defer staged.Cleanup()
	c.Set("audit_subject", countSubject(len(staged.files)))
	if err := staged.applyOverrides(); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_protocol_overrides", "Protocol overrides are invalid.")
		return
	}
	inspection, err := s.imports.Inspect(staged.files)
	if err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "inspected")
	c.JSON(http.StatusOK, inspection)
}

func (s *Server) commitImport(c *gin.Context) {
	if !s.acquireImport() {
		writeError(c, http.StatusConflict, "import_busy", "Another import is in progress.")
		return
	}
	defer s.releaseImport()
	setImportReadDeadline(c)
	allowed := map[string]bool{
		"protocol_overrides": true, "inspection_records": true, "metadata": true,
		"receipt": true, "trust_profile_policy": true, "library_revision": true,
	}
	staged, err := stageImportMultipart(c, s.runtimeDir, allowed)
	if err != nil {
		writeImportEnvelopeError(c, err)
		return
	}
	defer staged.Cleanup()
	c.Set("audit_subject", countSubject(len(staged.files)))
	if err := staged.applyOverrides(); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_protocol_overrides", "Protocol overrides are invalid.")
		return
	}
	var records []profiles.InspectionRecord
	if err := decodeStrictJSON(staged.fields["inspection_records"], &records, false); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_inspection_records", "Inspection records are invalid.")
		return
	}
	if err := rejectDuplicateJSONKeys(staged.fields["metadata"]); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_metadata", "Import metadata is invalid.")
		return
	}
	metadata, err := profiles.DecodeMetadataDocument(staged.fields["metadata"])
	if err != nil {
		writeError(c, http.StatusUnprocessableEntity, "invalid_metadata", "Import metadata is invalid.")
		return
	}
	receipt, err := exactTextField(staged.fields, "receipt", 128)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_receipt", "The inspection receipt is invalid.")
		return
	}
	trust, err := exactTextField(staged.fields, "trust_profile_policy", 5)
	if err != nil || trust != "true" {
		writeError(c, http.StatusUnprocessableEntity, "trust_required", "Confirm that you trust these profiles to change this host's network configuration.")
		return
	}
	// The client repeats the inspection revision as a dedicated strict part.
	revisionText, err := exactTextField(staged.fields, "library_revision", 20)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_library_revision", "The inspection revision is required.")
		return
	}
	revision, err := parseRevision(revisionText)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_library_revision", "The inspection revision is invalid.")
		return
	}
	result, err := s.imports.Commit(profiles.CommitRequest{
		Files: staged.files, LibraryRevision: revision, InspectionRecords: records, Metadata: metadata,
		Receipt: receipt, TrustProfilePolicy: true,
	})
	if err != nil {
		writeMappedError(c, err)
		return
	}
	response := struct {
		Records  []gin.H `json:"records"`
		Replayed bool    `json:"replayed"`
		Revision uint64  `json:"library_revision"`
	}{Records: make([]gin.H, len(result.Records)), Replayed: result.Replayed, Revision: result.Revision}
	for index, record := range result.Records {
		profile, err := s.manager.Profile(c.Request.Context(), record.Profile.ID)
		if err != nil {
			writeError(c, http.StatusInternalServerError, "outcome_ambiguous", "The import result could not be reconciled.")
			return
		}
		response.Records[index] = gin.H{"ordinal": record.Ordinal, "result": record.Result, "profile": profile}
	}
	c.Set("audit_outcome", "imported")
	c.JSON(http.StatusOK, response)
}

func (s *Server) patchProfile(c *gin.Context) {
	patch, err := decodeMetadataPatch(c.Request)
	if err != nil {
		if errors.Is(err, errMalformedMetadataPatch) {
			writeError(c, http.StatusBadRequest, "invalid_request", "The metadata request is malformed.")
			return
		}
		writeError(c, http.StatusUnprocessableEntity, "invalid_metadata", "Profile metadata is invalid.")
		return
	}
	id := c.Param("id")
	c.Set("audit_subject", id)
	updated, err := s.manager.UpdateMetadata(c.Request.Context(), id, patch)
	if err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "updated")
	c.JSON(http.StatusOK, updated)
}

func (s *Server) removeProfile(c *gin.Context) {
	if !requestBodyEmpty(c.Request) {
		writeError(c, http.StatusBadRequest, "invalid_request", "Profile removal does not accept a request body.")
		return
	}
	id := c.Param("id")
	c.Set("audit_subject", id)
	removed, err := s.manager.Remove(c.Request.Context(), id)
	if err != nil {
		writeMappedError(c, err)
		return
	}
	c.Set("audit_outcome", "removed")
	c.JSON(http.StatusOK, gin.H{"result": "removed", "profile": removed.Profile, "cleanup_pending": removed.CleanupPending})
}

func setImportReadDeadline(c *gin.Context) {
	controller := http.NewResponseController(c.Writer)
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Minute))
}

func (s *Server) acquireImport() bool {
	select {
	case <-s.importGate:
		return true
	default:
		return false
	}
}

func (s *Server) releaseImport() { s.importGate <- struct{}{} }

func countSubject(count int) string { return "count:" + formatInt(count) }

func writeError(c *gin.Context, status int, code, message string) {
	c.Set("audit_outcome", code)
	c.JSON(status, gin.H{"code": code, "error": message})
}

func writeErrorDetails(c *gin.Context, status int, code, message string, details []gin.H) {
	c.Set("audit_outcome", code)
	c.JSON(status, gin.H{"code": code, "error": message, "details": details})
}

func writeMappedError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, profiles.ErrNotFound):
		writeError(c, http.StatusNotFound, "profile_not_found", "The profile was not found.")
	case errors.Is(err, profiles.ErrReadOnly):
		writeError(c, http.StatusForbidden, "read_only", "Mutations are disabled.")
	case errors.Is(err, manager.ErrTransitionInProgress):
		writeError(c, http.StatusConflict, "transition_in_progress", "Another tunnel or library operation is in progress.")
	case errors.Is(err, manager.ErrActiveProfile):
		writeError(c, http.StatusConflict, "profile_active", "Disconnect this profile before removing it.")
	case errors.Is(err, manager.ErrManagedStateConflict), errors.Is(err, tunnel.ErrIdentityConflict):
		writeError(c, http.StatusConflict, "managed_state_conflict", "Managed tunnel state is conflicted.")
	case errors.Is(err, manager.ErrTransitionFailed):
		writeError(c, http.StatusServiceUnavailable, "transition_failed", "The tunnel transition failed. The current state has been reconciled where possible.")
	case errors.Is(err, profiles.ErrImportBusy):
		writeError(c, http.StatusConflict, "import_busy", "Another import is in progress.")
	case errors.Is(err, profiles.ErrStaleInspection):
		writeError(c, http.StatusConflict, "stale_inspection", "The library changed. Inspect these files again.")
	case errors.Is(err, profiles.ErrExpiredReceipt):
		writeError(c, http.StatusConflict, "inspection_expired", "The inspection expired. Inspect these files again.")
	case errors.Is(err, profiles.ErrInvalidReceipt):
		writeError(c, http.StatusBadRequest, "invalid_receipt", "The inspection receipt is invalid.")
	case errors.Is(err, profiles.ErrCapacity):
		writeError(c, http.StatusConflict, "library_capacity", "The profile library has reached its 100-profile limit.")
	case errors.Is(err, profiles.ErrConflict):
		writeError(c, http.StatusConflict, "library_conflict", "The profile library changed or contains a conflicting record.")
	case errors.Is(err, profiles.ErrInvalidMetadata):
		var metadataErr *profiles.MetadataValidationError
		var importErr *profiles.ImportMetadataError
		if errors.As(err, &metadataErr) {
			detail := gin.H{"field": metadataErr.Field, "code": metadataErr.Code}
			if errors.As(err, &importErr) {
				detail["file"] = importErr.File
			}
			writeErrorDetails(c, http.StatusUnprocessableEntity, "invalid_metadata", "Profile metadata is invalid.", []gin.H{detail})
			return
		}
		writeError(c, http.StatusUnprocessableEntity, "invalid_metadata", "Profile metadata is invalid.")
	case errors.Is(err, profiles.ErrInvalidManifest):
		writeError(c, http.StatusBadRequest, "invalid_preferences", "Preferences reference an unknown or duplicate profile.")
	case errors.Is(err, profiles.ErrOutcomeAmbiguous):
		writeError(c, http.StatusServiceUnavailable, "outcome_ambiguous", "The durable outcome is unknown. Refresh the library before retrying.")
	case errors.Is(err, tunnel.ErrUnavailable), errors.Is(err, tunnel.ErrObservationFailed):
		writeError(c, http.StatusServiceUnavailable, "protocol_unavailable", "Protocol state or tooling is unavailable.")
	default:
		writeError(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
	}
}

func writeImportEnvelopeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		writeError(c, http.StatusUnsupportedMediaType, "unsupported_media_type", "The import requires multipart/form-data.")
	case errors.Is(err, errRequestTooLarge):
		writeError(c, http.StatusRequestEntityTooLarge, "import_too_large", "The import exceeds its file, count, or request limit.")
	case errors.Is(err, errImportStaging):
		writeError(c, http.StatusInternalServerError, "import_staging_failed", "The import could not be staged.")
	default:
		writeError(c, http.StatusBadRequest, "invalid_multipart", "The import request is malformed.")
	}
}

func writeJSONEnvelopeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		writeError(c, http.StatusUnsupportedMediaType, "unsupported_media_type", "The request requires application/json.")
	case errors.Is(err, errRequestTooLarge):
		writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", "The request body exceeds its limit.")
	default:
		writeError(c, http.StatusBadRequest, "invalid_json", "The request body is malformed.")
	}
}
