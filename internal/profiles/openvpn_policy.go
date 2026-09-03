package profiles

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxOpenVPNLogicalLine = 16 << 10
	maxOpenVPNInlineBlock = 256 << 10
)

var openVPNInlineBlocks = map[string]struct{}{
	"ca": {}, "cert": {}, "key": {}, "tls-auth": {}, "tls-crypt": {}, "tls-crypt-v2": {},
}

var openVPNAllowedDirectives = map[string][2]int{
	"allow-compression": {1, 1}, "allow-pull-fqdn": {0, 0}, "auth": {1, 1}, "auth-nocache": {0, 0},
	"auth-retry": {1, 1}, "cipher": {1, 1}, "client": {0, 0}, "comp-lzo": {0, 1}, "compress": {0, 1},
	"connect-retry": {1, 2}, "connect-retry-max": {1, 1}, "connect-timeout": {1, 1}, "data-ciphers": {1, 1},
	"data-ciphers-fallback": {1, 1}, "dev": {1, 1}, "dev-type": {1, 1}, "dhcp-option": {2, 3},
	"explicit-exit-notify": {0, 1}, "fast-io": {0, 0}, "hand-window": {1, 1}, "inactive": {1, 2},
	"keepalive": {2, 2}, "key-direction": {1, 1}, "link-mtu": {1, 1}, "mssfix": {0, 2}, "mute-replay-warnings": {0, 0},
	"nobind": {0, 0}, "ns-cert-type": {1, 1}, "ping": {1, 1}, "ping-exit": {1, 1}, "ping-restart": {1, 1},
	"persist-key": {0, 0}, "persist-tun": {0, 0}, "peer-fingerprint": {1, 1}, "proto": {1, 1}, "pull": {0, 0},
	"pull-filter": {2, 2}, "rcvbuf": {1, 1}, "redirect-gateway": {0, 8}, "redirect-private": {0, 8},
	"remote": {1, 3}, "remote-cert-ku": {1, 8}, "remote-cert-tls": {1, 1}, "remote-random": {0, 0},
	"remote-random-hostname": {0, 0}, "reneg-sec": {1, 1}, "resolv-retry": {1, 1}, "route": {1, 4},
	"route-delay": {0, 2}, "route-gateway": {1, 1}, "route-ipv6": {1, 2}, "route-metric": {1, 1}, "route-nopull": {0, 0},
	"sndbuf": {1, 1}, "socket-flags": {1, 8}, "tcp-nodelay": {0, 0}, "tls-cipher": {1, 1},
	"tls-ciphersuites": {1, 1}, "tls-client": {0, 0}, "tls-exit": {0, 0}, "tls-version-max": {1, 2},
	"tls-version-min": {1, 2}, "topology": {1, 1}, "tran-window": {1, 1}, "tun-mtu": {1, 1}, "tun-mtu-extra": {1, 1},
	"verify-x509-name": {1, 2},
}

var openVPNDeniedDirectives = map[string]string{
	"askpass": "interactive credentials", "auth-gen-token": "interactive credentials", "auth-gen-token-secret": "credential files",
	"auth-user-pass": "interactive credentials", "auth-user-pass-verify": "executable hooks", "cd": "process ownership changes",
	"chroot": "process ownership changes", "client-connect": "executable hooks", "client-crresponse": "interactive challenges",
	"client-disconnect": "executable hooks", "config": "included configuration", "daemon": "process ownership changes",
	"down": "executable hooks", "down-pre": "executable hooks", "group": "process ownership changes", "http-proxy-user-pass": "credential files",
	"ipchange": "executable hooks", "learn-address": "executable hooks", "log": "arbitrary output paths", "log-append": "arbitrary output paths",
	"management": "management interfaces", "management-client": "management interfaces", "management-external-key": "management interfaces",
	"management-hold": "management interfaces", "management-query-passwords": "management interfaces", "management-signal": "management interfaces",
	"machine-readable-output": "diagnostic overrides", "plugin": "plugins", "route-up": "executable hooks", "script-security": "executable hooks",
	"secret": "static key files", "setenv-safe": "environment overrides", "socks-proxy": "proxy credential files", "status": "arbitrary output paths",
	"status-version": "arbitrary output paths", "syslog": "diagnostic overrides", "tls-verify": "executable hooks", "tmp-dir": "arbitrary output paths",
	"up": "executable hooks", "up-delay": "executable hooks", "up-restart": "executable hooks", "user": "process ownership changes",
	"verb": "diagnostic overrides", "writepid": "process ownership changes",
}

func ValidateOpenVPNImport(data []byte) error {
	if len(data) == 0 || len(data) > MaxProfileBytes || !utf8.Valid(data) {
		return &PolicyError{Code: "invalid_encoding", Message: "OpenVPN profile must be non-empty UTF-8 text no larger than 1 MiB"}
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	lineNumber := 0
	logical := ""
	block := ""
	blockBytes := 0
	seenBlocks := make(map[string]struct{})
	seenClient, seenRemote := false, false
	for {
		physical, readErr := reader.ReadString('\n')
		if len(physical) != 0 {
			lineNumber++
			physical = strings.TrimSuffix(strings.TrimSuffix(physical, "\n"), "\r")
			if len(physical) > maxOpenVPNLogicalLine {
				return &PolicyError{Line: lineNumber, Code: "line_too_long", Message: "configuration line exceeds 16 KiB"}
			}
			if err := validateOpenVPNCharacters(physical); err != nil {
				return &PolicyError{Line: lineNumber, Code: "control_character", Message: err.Error()}
			}
			trimmed := strings.TrimSpace(physical)
			if block != "" {
				if strings.EqualFold(trimmed, "</"+block+">") {
					seenBlocks[block] = struct{}{}
					block, blockBytes = "", 0
				} else {
					if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
						return &PolicyError{Line: lineNumber, Code: "nested_inline_block", Message: "inline blocks cannot be nested"}
					}
					blockBytes += len(physical) + 1
					if blockBytes > maxOpenVPNInlineBlock {
						return &PolicyError{Line: lineNumber, Code: "inline_block_too_large", Message: "inline block exceeds 256 KiB"}
					}
				}
			} else if name, opening, closing := openVPNBlockDelimiter(trimmed); opening || closing {
				if closing {
					return &PolicyError{Line: lineNumber, Code: "unexpected_inline_close", Message: "inline block closing delimiter has no matching opening delimiter"}
				}
				if _, supported := openVPNInlineBlocks[name]; !supported {
					return &PolicyError{Line: lineNumber, Code: "unsupported_inline_block", Message: "this inline block is not supported"}
				}
				if _, duplicate := seenBlocks[name]; duplicate {
					return &PolicyError{Line: lineNumber, Code: "duplicate_inline_block", Message: fmt.Sprintf("inline block %s may appear only once", name)}
				}
				block = name
			} else {
				continued, fragment, err := openVPNContinuation(physical)
				if err != nil {
					return &PolicyError{Line: lineNumber, Code: "invalid_directive", Message: err.Error()}
				}
				logical += fragment
				if len(logical) > maxOpenVPNLogicalLine {
					return &PolicyError{Line: lineNumber, Code: "line_too_long", Message: "logical configuration line exceeds 16 KiB"}
				}
				if !continued {
					directive, err := validateOpenVPNDirective(logical, lineNumber)
					if err != nil {
						return err
					}
					seenClient = seenClient || directive == "client" || directive == "tls-client"
					seenRemote = seenRemote || directive == "remote"
					logical = ""
				}
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return &PolicyError{Line: lineNumber, Code: "read_failed", Message: "OpenVPN profile could not be read"}
			}
			break
		}
	}
	if block != "" {
		return &PolicyError{Line: lineNumber, Code: "unterminated_inline_block", Message: fmt.Sprintf("inline block %s is not closed", block)}
	}
	if logical != "" {
		return &PolicyError{Line: lineNumber, Code: "dangling_continuation", Message: "configuration ends during a continued directive"}
	}
	if !seenClient || !seenRemote {
		return &PolicyError{Code: "missing_client_directive", Message: "OpenVPN profile requires client mode and at least one remote"}
	}
	return nil
}

func validateOpenVPNDirective(line string, lineNumber int) (string, error) {
	tokens, err := tokenizeOpenVPNLine(line)
	if err != nil {
		return "", &PolicyError{Line: lineNumber, Code: "invalid_directive", Message: err.Error()}
	}
	if len(tokens) == 0 {
		return "", nil
	}
	directive := strings.ToLower(strings.TrimLeft(tokens[0], "-"))
	if reason, denied := openVPNDeniedDirectives[directive]; denied || strings.HasPrefix(directive, "management-") {
		if !denied {
			reason = "management interfaces"
		}
		return "", &PolicyError{Line: lineNumber, Code: "unsafe_directive", Message: fmt.Sprintf("%s is not imported because it controls %s", directive, reason)}
	}
	if _, inline := openVPNInlineBlocks[directive]; inline {
		if len(tokens) != 2 || strings.ToLower(tokens[1]) != "[inline]" {
			return "", &PolicyError{Line: lineNumber, Code: "external_reference", Message: fmt.Sprintf("%s must use an inline block; referenced files are not imported", directive)}
		}
		return directive, nil
	}
	bounds, allowed := openVPNAllowedDirectives[directive]
	if !allowed {
		return "", &PolicyError{Line: lineNumber, Code: "unsupported_directive", Message: "this directive is not in the version 1 OpenVPN import policy"}
	}
	arguments := len(tokens) - 1
	if arguments < bounds[0] || arguments > bounds[1] {
		return "", &PolicyError{Line: lineNumber, Code: "invalid_directive", Message: fmt.Sprintf("%s has an unsupported argument count", directive)}
	}
	return directive, nil
}

func validateOpenVPNCharacters(line string) error {
	for _, char := range line {
		if unicode.IsControl(char) && char != '\t' {
			return errors.New("configuration contains a control character")
		}
	}
	return nil
}

func openVPNBlockDelimiter(line string) (name string, opening, closing bool) {
	if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' {
		return "", false, false
	}
	content := strings.TrimSpace(line[1 : len(line)-1])
	if strings.HasPrefix(content, "/") {
		name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(content, "/")))
		return name, false, name != ""
	}
	name = strings.ToLower(content)
	return name, name != "", false
}

func openVPNContinuation(line string) (bool, string, error) {
	inSingle, inDouble, escaped := false, false, false
	commentAt := -1
	for index, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && !inSingle {
			escaped = true
			continue
		}
		if char == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if char == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && (char == '#' || char == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			commentAt = index
			break
		}
	}
	content := line
	if commentAt >= 0 {
		content = line[:commentAt]
		escaped = false
		for _, char := range content {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			}
		}
	}
	trimmed := strings.TrimRight(content, " \t")
	if escaped && strings.HasSuffix(trimmed, "\\") {
		return true, strings.TrimSuffix(trimmed, "\\"), nil
	}
	if inSingle || inDouble {
		return false, "", errors.New("unterminated quote")
	}
	return false, content, nil
}

func tokenizeOpenVPNLine(line string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	inSingle, inDouble, escaped, started := false, false, false, false
	flush := func() {
		if started {
			tokens = append(tokens, token.String())
			token.Reset()
			started = false
		}
	}
	for index, char := range line {
		if escaped {
			token.WriteRune(char)
			started, escaped = true, false
			continue
		}
		if char == '\\' && !inSingle {
			escaped, started = true, true
			continue
		}
		if char == '\'' && !inDouble {
			inSingle, started = !inSingle, true
			continue
		}
		if char == '"' && !inSingle {
			inDouble, started = !inDouble, true
			continue
		}
		if !inSingle && !inDouble {
			if (char == '#' || char == ';') && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
				break
			}
			if char == ' ' || char == '\t' {
				flush()
				continue
			}
		}
		token.WriteRune(char)
		started = true
	}
	if escaped {
		return nil, errors.New("dangling escape")
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return tokens, nil
}
