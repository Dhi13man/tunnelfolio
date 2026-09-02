package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
)

const (
	defaultListenAddress = "127.0.0.1:50001"
	defaultStateDir      = "/var/lib/tunnelfolio"
	defaultRuntimeDir    = "/run/tunnelfolio/imports"
)

type options struct {
	listenAddress  string
	stateDir       string
	trustedProxy   bool
	proxyTokenFile string
	readOnly       bool
	showVersion    bool
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("tunnelfolio", flag.ContinueOnError)
	var result options
	flags.StringVar(&result.listenAddress, "listen", defaultListenAddress, "loopback HTTP listen address")
	flags.StringVar(&result.stateDir, "state-dir", defaultStateDir, "private mutable state directory")
	flags.BoolVar(&result.trustedProxy, "trusted-proxy", false, "require authenticated HTTPS reverse-proxy headers")
	flags.StringVar(&result.proxyTokenFile, "proxy-token-file", "", "private proxy credential file (required with --trusted-proxy)")
	flags.BoolVar(&result.readOnly, "read-only", false, "disable all state-changing operations")
	flags.BoolVar(&result.showVersion, "version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if result.showVersion {
		return result, nil
	}
	if err := validateListenAddress(result.listenAddress); err != nil {
		return options{}, err
	}
	if result.stateDir == "" {
		return options{}, errors.New("--state-dir must not be empty")
	}
	if result.trustedProxy && result.proxyTokenFile == "" {
		return options{}, errors.New("--trusted-proxy requires --proxy-token-file")
	}
	if !result.trustedProxy && result.proxyTokenFile != "" {
		return options{}, errors.New("--proxy-token-file requires --trusted-proxy")
	}
	if !result.trustedProxy && !result.readOnly {
		return options{}, errors.New("mutable mode requires --trusted-proxy and --proxy-token-file; use --read-only for unauthenticated loopback inventory")
	}
	return result, nil
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
	return errors.New("listen address must be loopback; expose Tunnelfolio through a same-host authenticated proxy")
}
