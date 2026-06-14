package main

import "encoding/json"

// Wire protocol for the RPN Direct control channel (JSON over WSS).
// See ARCHITECTURE.md for the full lifecycle. Every frame is an Envelope.

const (
	TypeHello     = "hello"     // C->S  register
	TypeWelcome   = "welcome"   // S->C  registration accepted
	TypePeers     = "peers"     // S->C  current peer list (pushed on any change)
	TypeEndpoints = "endpoints" // C->S  my gathered ICE candidates
	TypeConnect   = "connect"   // C->S  please introduce me to this peer
	TypePunch     = "punch"     // S->C  start simultaneous-open now
	TypeResult    = "result"    // C->S  outcome of a punch attempt
	TypeRelay     = "relay"     // S->C  fall back to the TURN relay (with credentials)
	TypePing      = "ping"      // bidi  keepalive
	TypePong      = "pong"      // bidi  keepalive
)

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

// ── payloads ──────────────────────────────────────────────────────────────────

type Hello struct {
	AccessCode string `json:"accessCode"`
	PubKey     string `json:"pubKey"` // WireGuard public key (base64)
	Role       string `json:"role"`   // RoleExit | RoleClient
	Name       string `json:"name"`
}

type Welcome struct {
	SelfIP        string `json:"selfIP"`        // assigned VPN /32, e.g. 10.99.0.101/32
	NetworkID     string `json:"networkID"`     // which network this peer belongs to
	STUNEndpoint  string `json:"stunEndpoint"`  // primary STUN ip:port (RFC 5389)
	STUN2Endpoint string `json:"stun2Endpoint"` // secondary STUN ip:port (RFC 5780 dual-port NAT classification)
	RelayEndpoint string `json:"relayEndpoint"` // TURN relay ip:port (fallback)
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
	AtUnixMs   int64       `json:"atUnixMs"` // synchronized start instant for simultaneous-open
}

type Result struct {
	PeerPubKey string `json:"peerPubKey"`
	OK         bool   `json:"ok"`
	Via        string `json:"via"`  // "direct" | "relay"
	Addr       string `json:"addr"` // the winning remote address
}

// Relay carries TURN allocation credentials so the peer can authenticate.
// Username and Password are time-limited HMAC-SHA1 credentials (24h TTL).
// The relay is sent immediately on connect (before punch) so the peer has a
// working path right away while hole-punching runs in the background.
type Relay struct {
	PeerPubKey   string `json:"peerPubKey"`
	RelaySession string `json:"relaySession"` // shared session token (pairKey of the two pubkeys)
	Username     string `json:"username"`     // TURN username: "{expiry_unix}:{peer_short}"
	Password     string `json:"password"`     // TURN password: base64(HMAC-SHA1(secret, username))
}
