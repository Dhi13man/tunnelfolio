package tunnel

import (
	"context"
	"errors"
	"time"
)

const (
	ProtocolOpenVPN   = "openvpn"
	ProtocolWireGuard = "wireguard"
	DefaultTimeout    = 30 * time.Second
)

var (
	ErrUnavailable       = errors.New("protocol tooling is unavailable")
	ErrIdentityConflict  = errors.New("managed runtime identity conflict")
	ErrObservationFailed = errors.New("managed runtime observation failed")
	ErrOutputLimit       = errors.New("command output exceeded its limit")
	ErrCleanupUnproved   = errors.New("failed activation cleanup could not be proved")
)

type Profile struct {
	ID                       string
	Protocol                 string
	Identifier               string
	Path                     string
	WireGuardPublicKeySHA256 string
}

type Observation struct {
	ProfileID  string
	Protocol   string
	Identifier string
}

type UnexpectedExit struct {
	ProfileID     string
	ExecutionPath string
	CleanupProved bool
}

type UnexpectedExitSource interface {
	SetUnexpectedExitHandler(func(UnexpectedExit))
}

type WireGuardPeerStatus struct {
	Endpoint        string `json:"endpoint,omitempty"`
	LatestHandshake int64  `json:"latest_handshake,omitempty"`
	ReceivedBytes   uint64 `json:"received_bytes"`
	SentBytes       uint64 `json:"sent_bytes"`
}

type ProtocolStatus struct {
	State         string                `json:"state"`
	ReceivedBytes uint64                `json:"received_bytes,omitempty"`
	SentBytes     uint64                `json:"sent_bytes,omitempty"`
	Peers         []WireGuardPeerStatus `json:"peers,omitempty"`
}

type Backend interface {
	Protocol() string
	Available(context.Context) error
	Observe(context.Context, []Profile) ([]Observation, error)
	Start(context.Context, Profile) error
	Stop(context.Context, Profile) error
	Status(context.Context, Profile) (ProtocolStatus, error)
	Shutdown(context.Context) error
}
