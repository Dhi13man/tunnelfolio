package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var templates embed.FS

const (
	defaultListenAddress = "127.0.0.1:50001"
	defaultProfilesDir   = "/etc/tunnelfolio/profiles"
	defaultStateDir      = "/var/lib/tunnelfolio"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type options struct {
	listenAddress  string
	profilesDir    string
	stateDir       string
	trustedProxy   bool
	proxyTokenFile string
	readOnly       bool
	showVersion    bool
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("tunnelfolio", flag.ContinueOnError)
	var opts options
	flags.StringVar(&opts.listenAddress, "listen", defaultListenAddress, "HTTP listen address")
	flags.StringVar(&opts.profilesDir, "profiles-dir", defaultProfilesDir, "root-owned VPN profile directory")
	flags.StringVar(&opts.stateDir, "state-dir", defaultStateDir, "mutable state directory")
	flags.BoolVar(&opts.trustedProxy, "trusted-proxy", false, "require authenticated HTTPS reverse-proxy headers")
	flags.StringVar(&opts.proxyTokenFile, "proxy-token-file", "", "root-owned proxy credential file (required with --trusted-proxy)")
	flags.BoolVar(&opts.readOnly, "read-only", false, "disable all state-changing operations")
	flags.BoolVar(&opts.showVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if opts.showVersion {
		return opts, nil
	}
	if err := validateListenAddress(opts.listenAddress); err != nil {
		return options{}, err
	}
	if opts.trustedProxy && opts.proxyTokenFile == "" {
		return options{}, errors.New("--trusted-proxy requires --proxy-token-file")
	}
	if !opts.trustedProxy && opts.proxyTokenFile != "" {
		return options{}, errors.New("--proxy-token-file requires --trusted-proxy")
	}
	if !opts.trustedProxy && !opts.readOnly {
		return options{}, errors.New("mutable mode requires --trusted-proxy and --proxy-token-file; use --read-only for unauthenticated loopback inventory")
	}
	return opts, nil
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("listen address must be loopback; expose the service through a local reverse proxy")
}

func newRouter(server *Server) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery(), requestContext(), requestLogger(), securityHeaders())
	if server.trustedProxy {
		router.Use(requireTrustedProxy(server.proxyToken, func(c *gin.Context) {
			server.auditActor(c, "", auditOperationForRequest(c.Request), "", "proxy_auth_required", false)
		}))
	}
	tmplFS, err := fs.Sub(templates, "templates")
	if err != nil {
		return nil, fmt.Errorf("open embedded templates: %w", err)
	}
	tmpl, err := template.ParseFS(tmplFS, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded templates: %w", err)
	}
	router.SetHTMLTemplate(tmpl)
	router.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "index.html", nil) })
	for path, contentType := range map[string]string{"app.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"} {
		assetPath, assetType := path, contentType
		router.GET("/assets/"+assetPath, func(c *gin.Context) {
			content, err := templates.ReadFile("templates/" + assetPath)
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			c.Data(http.StatusOK, assetType, content)
		})
	}
	router.GET("/healthz", server.handleHealth)
	router.GET("/api/status", server.handleStatus)
	router.GET("/api/profiles", server.handleProfiles)
	router.POST("/api/connect", server.mutation("connect", server.handleConnect))
	router.POST("/api/disconnect", server.mutation("disconnect", server.handleDisconnect))
	router.GET("/api/preferences", server.handleGetPreferences)
	router.PUT("/api/preferences", server.mutation("preferences", server.handleSavePreferences))
	return router, nil
}

func auditOperationForRequest(request *http.Request) string {
	if request == nil {
		return "authentication"
	}
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/api/connect":
		return "connect"
	case request.Method == http.MethodPost && request.URL.Path == "/api/disconnect":
		return "disconnect"
	case request.Method == http.MethodPut && request.URL.Path == "/api/preferences":
		return "preferences"
	default:
		return "authentication"
	}
}

func buildBackends(catalog *ProfileCatalog) map[string]managedBackend {
	backends := make(map[string]managedBackend, 2)
	_, catalogErr := catalog.Profiles(BackendWireGuard)
	wgRunner, err := newExecRunnerFor("wg", "wg-quick")
	if catalogErr != nil {
		backends[BackendWireGuard] = unavailableBackend{kind: BackendWireGuard, err: catalogErr}
	} else if err != nil {
		backends[BackendWireGuard] = unavailableBackend{kind: BackendWireGuard, err: err}
	} else {
		backends[BackendWireGuard] = &wireGuardAdapter{backend: NewWireGuardBackend(catalog, wgRunner, 100*time.Millisecond)}
	}
	_, catalogErr = catalog.Profiles(BackendOpenVPN)
	openVPNPath, err := resolveSecureCommand("openvpn")
	if catalogErr != nil {
		backends[BackendOpenVPN] = unavailableBackend{kind: BackendOpenVPN, err: catalogErr}
	} else if err != nil {
		backends[BackendOpenVPN] = unavailableBackend{kind: BackendOpenVPN, err: err}
	} else {
		backend, createErr := NewOpenVPNBackend(OpenVPNBackendOptions{
			Command:      openVPNPath,
			Inspector:    OpenVPNConfigInspector{},
			ReadyTimeout: commandTimeout,
			Log:          func(message string) { log.Printf("openvpn: %s", message) },
		})
		if createErr != nil {
			backends[BackendOpenVPN] = unavailableBackend{kind: BackendOpenVPN, err: createErr}
		} else {
			backends[BackendOpenVPN] = &openVPNAdapter{backend: backend, catalog: catalog}
		}
	}
	return backends
}

func run(ctx context.Context, opts options) error {
	if !opts.readOnly && os.Geteuid() != 0 {
		return errors.New("mutable mode requires root privileges")
	}
	catalog, err := NewProfileCatalog(opts.profilesDir)
	if err != nil {
		return err
	}
	server, err := NewServer(opts, catalog, buildBackends(catalog))
	if err != nil {
		return err
	}
	router, err := newRouter(server)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              opts.listenAddress,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("tunnelfolio listening on %s (profiles: %s, read-only: %t)", opts.listenAddress, opts.profilesDir, opts.readOnly)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpErr := httpServer.Shutdown(shutdownCtx)
		backendErr := server.shutdown(shutdownCtx)
		return errors.Join(httpErr, backendErr)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if opts.showVersion {
		fmt.Printf("tunnelfolio %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, opts); err != nil {
		log.Fatal(err)
	}
}

func statePaths(stateDir string) (string, string) {
	return filepath.Join(stateDir, "state.json"), filepath.Join(stateDir, "preferences.json")
}
