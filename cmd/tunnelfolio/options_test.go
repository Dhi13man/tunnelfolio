package main

import (
	"strings"
	"testing"
)

func TestParseOptionsRequiresLoopbackAndMutationAuthentication(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "mutable unauthenticated", args: nil, want: "mutable mode requires"},
		{name: "non-loopback", args: []string{"--read-only", "--listen", "0.0.0.0:50001"}, want: "listen address must be loopback"},
		{name: "token without mode", args: []string{"--read-only", "--proxy-token-file", "/token"}, want: "requires --trusted-proxy"},
		{name: "mode without token", args: []string{"--trusted-proxy"}, want: "requires --proxy-token-file"},
		{name: "removed profiles dir", args: []string{"--profiles-dir", "/etc/old"}, want: "flag provided but not defined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOptions(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseOptionsAcceptsReadOnlyAndAuthenticatedMutableModes(t *testing.T) {
	readOnly, err := parseOptions([]string{"--read-only", "--listen", "[::1]:0"})
	if err != nil || !readOnly.readOnly {
		t.Fatalf("read-only options = %+v, %v", readOnly, err)
	}
	mutable, err := parseOptions([]string{"--trusted-proxy", "--proxy-token-file", "/etc/tunnelfolio/proxy-token"})
	if err != nil || !mutable.trustedProxy || mutable.readOnly {
		t.Fatalf("mutable options = %+v, %v", mutable, err)
	}
}

func TestVersionDoesNotRequireRuntimeOptions(t *testing.T) {
	options, err := parseOptions([]string{"--version"})
	if err != nil || !options.showVersion {
		t.Fatalf("version options = %+v, %v", options, err)
	}
}
