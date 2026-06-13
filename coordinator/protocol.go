package main

import "encoding/json"

// Wire protocol for the RPN Direct control channel (JSON over WSS).
// See ARCHITECTURE.md for the lifecycle. Every frame is an Envelope; Data is the
// type-specific payload below.

const (
	TypeHello     = "hello"     // C->S  register
	TypeWelcome   = "welcome"   // S->C  registration accepted
	TypePeers     = "peers"     // S->C  current peer list (pushed on any change)
	TypeEndpoints = "endpoints" // C->S  my gathered ICE candidates
	TypeConnect   = "connect"   // C->S  please introduce me to this peer
	TypePunch     = "punch"     // S->C  start simultaneous-open now
	TypeResult    = "result"    // C->S  outcome of a punch attempt
	TypeRelay     = "relay"     // S->C  fall back to the TURN relay
	TypePing      = "ping"      // bidi  keepalive
	TypePong      = "pong"      // bidi  keepalive
)

// Role of a peer in the network.
const (
	RoleExit   = "exit"   // residential egress (Pi/PC in India)
	RoleClient = "client" // customer device wanting to egress via an exit
)

// Candidate is one ICE candidate (host / srflx / relay).
type Candidate struct {
	Type string `json:"type"` // "host" | "srflx" | "relay"
	Addr string `json:"addr"` // ip:port
}

// Envelope wraps every frame.
type Envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

func encode(t string, payload any) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return json.Marshal(Envelope{Type: t, Data: raw})
}

// ---- payloads ----

type Hello struct {
	AccessCode string `json:"accessCode"`
	PubKey     string `json:"pubKey"` // WireGuard public key (base64), the peer's identity
	Role       string `json:"role"`   // RoleExit | RoleClient
	Name       string `json:"name"`
}

type Welcome struct {
	SelfIP        string `json:"selfIP"`        // assigned VPN /32, e.g. 10.99.0.101/32
	NetworkID     string `json:"networkID"`     // which network this peer belongs to
	STUNEndpoint  string `json:"stunEndpoint"`  // ip:port of the coordinator's STUN responder
	RelayEndpoint string `json:"relayEndpoint"` // ip:port of the TURN relay (fallback)
}

type PeerInfo struct {
	PubKey     string      `json:"pubKey"`
	Role       string      `json:"role"`
	VPNIP      string      `json:"vpnIP"`
	Candidates []Candidate `json:"candidates"`
	DirectOK   bool        `json:"directOK"` // last known: a direct path exists
}

type Peers struct {
	Peers []PeerInfo `json:"peers"`
}

type Endpoints struct {
	Candidates []Candidate `json:"candidates"`
}

type Connect struct {
	PeerPubKey string `json:"peerPubKey"`
}

type Punch struct {
	PeerPubKey string      `json:"peerPubKey"`
	Candidates []Candidate `json:"candidates"`
	AtUnixMs   int64       `json:"atUnixMs"` // synchronized start instant
}

type Result struct {
	PeerPubKey string `json:"peerPubKey"`
	OK         bool   `json:"ok"`
	Via        string `json:"via"`  // "direct" | "relay"
	Addr       string `json:"addr"` // the winning candidate pair (remote side)
}

type Relay struct {
	PeerPubKey   string `json:"peerPubKey"`
	RelaySession string `json:"relaySession"` // TURN allocation / forwarding token
}
