package profiles

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxWireGuardPeers = 32

type wireGuardSection struct {
	kind   string
	line   int
	values map[string][]string
}

func ValidateWireGuardImport(data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxProfileBytes || !utf8.Valid(data) {
		return "", &PolicyError{Code: "invalid_encoding", Message: "WireGuard profile must be non-empty UTF-8 text no larger than 1 MiB"}
	}
	sections, err := parseWireGuardSections(data)
	if err != nil {
		return "", err
	}
	if len(sections) < 2 || sections[0].kind != "interface" {
		return "", &PolicyError{Code: "invalid_structure", Message: "WireGuard profile requires one Interface section followed by Peer sections"}
	}
	peerCount := len(sections) - 1
	if peerCount < 1 || peerCount > maxWireGuardPeers {
		return "", &PolicyError{Code: "peer_limit", Message: "WireGuard profile requires between 1 and 32 peers"}
	}
	if err := validateWireGuardInterface(sections[0]); err != nil {
		return "", err
	}
	for _, section := range sections[1:] {
		if section.kind != "peer" {
			return "", &PolicyError{Line: section.line, Code: "invalid_structure", Message: "only Peer sections may follow Interface"}
		}
		if err := validateWireGuardPeer(section); err != nil {
			return "", err
		}
	}
	privateKey, err := decodeWireGuardKey(singleValue(sections[0], "privatekey"))
	if err != nil {
		return "", &PolicyError{Line: sections[0].line, Code: "invalid_private_key", Message: "Interface PrivateKey must be a 32-byte base64 key"}
	}
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return "", &PolicyError{Line: sections[0].line, Code: "invalid_private_key", Message: "Interface PrivateKey is not a valid X25519 key"}
	}
	digest := sha256.Sum256(key.PublicKey().Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func parseWireGuardSections(data []byte) ([]wireGuardSection, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	sections := make([]wireGuardSection, 0, 2)
	var current *wireGuardSection
	for index, raw := range lines {
		lineNumber := index + 1
		if len(raw) > 16<<10 {
			return nil, &PolicyError{Line: lineNumber, Code: "line_too_long", Message: "configuration line exceeds 16 KiB"}
		}
		for _, char := range raw {
			if unicode.IsControl(char) && char != '\t' {
				return nil, &PolicyError{Line: lineNumber, Code: "control_character", Message: "configuration contains a control character"}
			}
		}
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, &PolicyError{Line: lineNumber, Code: "invalid_section", Message: "section header is malformed"}
			}
			kind := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			if kind != "interface" && kind != "peer" {
				return nil, &PolicyError{Line: lineNumber, Code: "unsupported_section", Message: "only Interface and Peer sections are supported"}
			}
			if kind == "interface" && len(sections) != 0 {
				return nil, &PolicyError{Line: lineNumber, Code: "duplicate_interface", Message: "WireGuard profile must contain exactly one Interface section"}
			}
			sections = append(sections, wireGuardSection{kind: kind, line: lineNumber, values: make(map[string][]string)})
			current = &sections[len(sections)-1]
			continue
		}
		if current == nil {
			return nil, &PolicyError{Line: lineNumber, Code: "missing_section", Message: "configuration values must be inside a section"}
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, &PolicyError{Line: lineNumber, Code: "invalid_assignment", Message: "configuration value must use key = value"}
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, &PolicyError{Line: lineNumber, Code: "invalid_assignment", Message: "configuration key and value must be non-empty"}
		}
		if _, denied := map[string]struct{}{"preup": {}, "postup": {}, "predown": {}, "postdown": {}, "saveconfig": {}}[key]; denied {
			return nil, &PolicyError{Line: lineNumber, Code: "executable_hook", Message: "WireGuard hooks and SaveConfig are not imported"}
		}
		allowed := wireGuardInterfaceKeys
		if current.kind == "peer" {
			allowed = wireGuardPeerKeys
		}
		if _, ok := allowed[key]; !ok {
			return nil, &PolicyError{Line: lineNumber, Code: "unsupported_key", Message: fmt.Sprintf("this key is not supported in a %s section", current.kind)}
		}
		if len(current.values[key]) != 0 && key != "address" && key != "dns" {
			return nil, &PolicyError{Line: lineNumber, Code: "duplicate_key", Message: fmt.Sprintf("%s may appear only once in this section", key)}
		}
		current.values[key] = append(current.values[key], value)
	}
	return sections, nil
}

var wireGuardInterfaceKeys = map[string]struct{}{
	"address": {}, "dns": {}, "listenport": {}, "mtu": {}, "privatekey": {}, "table": {},
}

var wireGuardPeerKeys = map[string]struct{}{
	"allowedips": {}, "endpoint": {}, "persistentkeepalive": {}, "presharedkey": {}, "publickey": {},
}

func validateWireGuardInterface(section wireGuardSection) error {
	if len(section.values["privatekey"]) != 1 || len(section.values["address"]) == 0 {
		return &PolicyError{Line: section.line, Code: "missing_interface_value", Message: "Interface requires PrivateKey and Address"}
	}
	if _, err := decodeWireGuardKey(singleValue(section, "privatekey")); err != nil {
		return &PolicyError{Line: section.line, Code: "invalid_private_key", Message: "Interface PrivateKey must be a 32-byte base64 key"}
	}
	for _, value := range section.values["address"] {
		if err := validatePrefixList(value); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_address", Message: "Interface Address must contain valid IP prefixes"}
		}
	}
	for _, value := range section.values["dns"] {
		for _, item := range splitList(value) {
			if _, err := netip.ParseAddr(item); err != nil {
				return &PolicyError{Line: section.line, Code: "invalid_dns", Message: "Interface DNS accepts IP addresses only"}
			}
		}
	}
	if value := singleValue(section, "listenport"); value != "" {
		if err := validateUintRange(value, 1, 65535); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_listen_port", Message: "ListenPort must be between 1 and 65535"}
		}
	}
	if value := singleValue(section, "mtu"); value != "" {
		if err := validateUintRange(value, 576, 65535); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_mtu", Message: "MTU must be between 576 and 65535"}
		}
	}
	if value := strings.ToLower(singleValue(section, "table")); value != "" && value != "auto" && value != "off" {
		if err := validateUintRange(value, 1, 1<<32-1); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_table", Message: "Table must be auto, off, or a positive 32-bit table number"}
		}
	}
	return nil
}

func validateWireGuardPeer(section wireGuardSection) error {
	for _, key := range []string{"publickey", "endpoint", "allowedips"} {
		if len(section.values[key]) != 1 {
			return &PolicyError{Line: section.line, Code: "missing_peer_value", Message: "Peer requires PublicKey, Endpoint, and AllowedIPs"}
		}
	}
	if _, err := decodeWireGuardKey(singleValue(section, "publickey")); err != nil {
		return &PolicyError{Line: section.line, Code: "invalid_public_key", Message: "Peer PublicKey must be a 32-byte base64 key"}
	}
	if value := singleValue(section, "presharedkey"); value != "" {
		if _, err := decodeWireGuardKey(value); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_preshared_key", Message: "Peer PresharedKey must be a 32-byte base64 key"}
		}
	}
	if err := validatePrefixList(singleValue(section, "allowedips")); err != nil {
		return &PolicyError{Line: section.line, Code: "invalid_allowed_ips", Message: "Peer AllowedIPs must contain valid IP prefixes"}
	}
	if err := validateEndpoint(singleValue(section, "endpoint")); err != nil {
		return &PolicyError{Line: section.line, Code: "invalid_endpoint", Message: "Peer Endpoint must be a hostname or IP address with a port"}
	}
	if value := singleValue(section, "persistentkeepalive"); value != "" {
		if err := validateUintRange(value, 0, 65535); err != nil {
			return &PolicyError{Line: section.line, Code: "invalid_keepalive", Message: "PersistentKeepalive must be between 0 and 65535"}
		}
	}
	return nil
}

func validateEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("invalid endpoint")
	}
	if err := validateUintRange(port, 1, 65535); err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return errors.New("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid hostname")
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
				return errors.New("invalid hostname")
			}
		}
	}
	return nil
}

func validatePrefixList(value string) error {
	items := splitList(value)
	if len(items) == 0 {
		return errors.New("empty prefix list")
	}
	for _, item := range items {
		if _, err := netip.ParsePrefix(item); err != nil {
			return err
		}
	}
	return nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func singleValue(section wireGuardSection, key string) string {
	if len(section.values[key]) != 1 {
		return ""
	}
	return section.values[key][0]
}

func decodeWireGuardKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid WireGuard key")
	}
	return decoded, nil
}

func validateUintRange(value string, minimum, maximum uint64) error {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number < minimum || number > maximum {
		return errors.New("value is outside allowed range")
	}
	return nil
}
