package profiles

import "fmt"

const ImportPolicyVersion = 1

type PolicyIssue struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PolicyResult struct {
	Protocol                 string
	WireGuardPublicKeySHA256 string
}

type PolicyError struct {
	Line    int
	Code    string
	Message string
}

func (e *PolicyError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Message)
	}
	return e.Message
}

func ValidateImportedProfile(protocol string, data []byte) (PolicyResult, error) {
	switch protocol {
	case ProtocolOpenVPN:
		if err := ValidateOpenVPNImport(data); err != nil {
			return PolicyResult{}, err
		}
		return PolicyResult{Protocol: protocol}, nil
	case ProtocolWireGuard:
		identity, err := ValidateWireGuardImport(data)
		if err != nil {
			return PolicyResult{}, err
		}
		return PolicyResult{Protocol: protocol, WireGuardPublicKeySHA256: identity}, nil
	default:
		return PolicyResult{}, &PolicyError{Code: "unsupported_protocol", Message: "the profile protocol is not supported"}
	}
}
