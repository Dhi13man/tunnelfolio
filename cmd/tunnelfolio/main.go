package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Dhi13man/tunnelfolio/internal/httpapi"
	"github.com/Dhi13man/tunnelfolio/internal/manager"
	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/tunnel"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	options, err := parseOptions(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if options.showVersion {
		fmt.Printf("tunnelfolio %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, options); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, options options) error {
	if !options.readOnly && os.Geteuid() != 0 {
		return errors.New("mutable mode requires root privileges")
	}
	store, err := profiles.OpenStore(profiles.StoreOptions{
		Root: options.stateDir, RequiredUID: os.Geteuid(), ReadOnly: options.readOnly,
	})
	if err != nil {
		return err
	}
	defer store.Close()

	backends, wireGuardObserver, wireGuardRunner := buildBackends()
	managed, err := manager.New(manager.Options{Store: store, Backends: backends, ReadOnly: options.readOnly})
	if err != nil {
		return err
	}
	var checker profiles.CompatibilityChecker = profiles.CompatibilityCheckFunc(func([]byte) error { return tunnel.ErrUnavailable })
	var runtimeNameAvailable func(string) (bool, error)
	if wireGuardRunner != nil {
		checker = tunnel.WireGuardCompatibilityChecker{Runner: wireGuardRunner, RuntimeDir: defaultRuntimeDir, Timeout: 10 * time.Second}
	}
	if wireGuardObserver != nil {
		runtimeNameAvailable = func(identifier string) (bool, error) {
			checkCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			output, err := wireGuardObserver.Run(checkCtx, "wg", "show", "interfaces")
			if err != nil {
				return false, tunnel.ErrObservationFailed
			}
			for _, active := range strings.Fields(string(output)) {
				if active == identifier {
					return false, nil
				}
			}
			return true, nil
		}
	}
	imports, err := profiles.NewImportService(profiles.ImportServiceOptions{
		Store: store, WireGuardChecker: checker, RuntimeNameAvailable: runtimeNameAvailable,
		CommitAdmission: managed.AcquireLibraryOperation,
	})
	if err != nil {
		return err
	}
	var proxyToken []byte
	if options.trustedProxy {
		proxyToken, err = httpapi.LoadProxyToken(options.proxyTokenFile)
		if err != nil {
			return fmt.Errorf("load proxy token: %w", err)
		}
	}
	handler, err := httpapi.New(httpapi.Options{
		Manager: managed, Imports: imports, RuntimeDir: defaultRuntimeDir,
		TrustedProxy: options.trustedProxy, ProxyToken: proxyToken, ReadOnly: options.readOnly,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", options.listenAddress)
	if err != nil {
		return fmt.Errorf("bind Tunnelfolio listener: %w", err)
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
		WriteTimeout: 130 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	go managed.ReconcileStartup(ctx)
	log.Printf("tunnelfolio listening on %s (read-only: %t)", options.listenAddress, options.readOnly)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return errors.Join(server.Shutdown(shutdownCtx), managed.Shutdown(shutdownCtx))
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return errors.Join(err, managed.Shutdown(shutdownCtx))
	}
}

func buildBackends() (map[string]tunnel.Backend, *tunnel.ExecRunner, *tunnel.ExecRunner) {
	result := make(map[string]tunnel.Backend, 2)
	var wireGuardObserver, wireGuardRunner *tunnel.ExecRunner
	wgPath, wgErr := tunnel.ResolveSecureCommand("wg")
	if wgErr == nil {
		paths := map[string]string{"wg": wgPath}
		wgQuickPath, wgQuickErr := tunnel.ResolveSecureCommand("wg-quick")
		if wgQuickErr == nil {
			paths["wg-quick"] = wgQuickPath
		}
		wireGuardObserver, _ = tunnel.NewPinnedExecRunner(paths, 0)
		if wgQuickErr == nil {
			wireGuardRunner = wireGuardObserver
			result[profiles.ProtocolWireGuard] = tunnel.NewWireGuardBackend(wireGuardObserver, 100*time.Millisecond)
		} else {
			result[profiles.ProtocolWireGuard] = tunnel.NewWireGuardObservationBackend(wireGuardObserver)
		}
	}
	openVPNCommand, err := tunnel.ResolveSecureCommand("openvpn")
	if err == nil {
		backend, backendErr := tunnel.NewOpenVPNBackend(tunnel.OpenVPNBackendOptions{
			Command: openVPNCommand, Inspector: tunnel.OpenVPNConfigInspector{}, ReadyTimeout: tunnel.DefaultTimeout,
			Log: func(message string) { log.Printf("openvpn: %s", message) },
		})
		if backendErr == nil {
			adapter, adapterErr := tunnel.NewOpenVPNAdapter(backend)
			if adapterErr == nil {
				result[profiles.ProtocolOpenVPN] = adapter
			}
		}
	}
	return result, wireGuardObserver, wireGuardRunner
}
