package core

import "encoding/json"

// Wire protocol — JSON over WSS. MUST stay byte-compatible with the coordinator's
// coordinator/protocol.go. The only additions are Ufrag/Pwd (ICE short-term
// credentials) and full candidate SDP strings carried in Candidate.Addr.

const (
	TypeHello     = "hello"
	TypeWelcome   = "welcome"
	TypePeers     = "peers"
	TypeEndpoints = "endpoints"
	TypeConnect   = "connect"
	TypePunch     = "punch"
	TypeResult    = "result"
	TypeRelay     = "relay"
	TypeOffer     = "offer"  // S->exit: a client wants in; carries the client's per-session ICE creds
	TypeAnswer    = "answer" // exit->S: the exit's per-session ICE creds for that client
	TypePing      = "ping"
	TypePong      = "pong"
)

const (
	RoleExit   = "exit"
	RoleClient = "client"
)

// Candidate carries a pion ICE candidate. Addr holds candidate.Marshal()
// (full SDP "candidate:..." string), not just ip:port, so the remote agent can
// reconstruct it with ice.UnmarshalCandidate.
type Candidate struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

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

type Hello struct {
	AccessCode string `json:"accessCode"`
	PubKey     string `json:"pubKey"`
	Role       string `json:"role"`
	Name       string `json:"name"`
}

type Welcome struct {
	SelfIP        string `json:"selfIP"`
	NetworkID     string `json:"networkID"`
	STUNEndpoint  string `json:"stunEndpoint"`
	STUN2Endpoint string `json:"stun2Endpoint"`
	RelayEndpoint string `json:"relayEndpoint"`
}

type PeerInfo struct {
	PubKey     string      `json:"pubKey"`
	Role       string      `json:"role"`
	VPNIP      string      `json:"vpnIP"`
	Candidates []Candidate `json:"candidates"`
	DirectOK   bool        `json:"directOK"`
	Ufrag      string      `json:"ufrag"` // ICE short-term cred
	Pwd        string      `json:"pwd"`   // ICE short-term cred
}

type Peers struct {
	Peers []PeerInfo `json:"peers"`
}

type Endpoints struct {
	Candidates []Candidate `json:"candidates"`
	Ufrag      string      `json:"ufrag"`
	Pwd        string      `json:"pwd"`
}

type Connect struct {
	PeerPubKey string `json:"peerPubKey"`
}

type Punch struct {
	PeerPubKey string      `json:"peerPubKey"`
	Candidates []Candidate `json:"candidates"`
	AtUnixMs   int64       `json:"atUnixMs"`
	Ufrag      string      `json:"ufrag"`
	Pwd        string      `json:"pwd"`
}

type Result struct {
	PeerPubKey string `json:"peerPubKey"`
	OK         bool   `json:"ok"`
	Via        string `json:"via"`
	Addr       string `json:"addr"`
}

type Relay struct {
	PeerPubKey   string `json:"peerPubKey"`
	RelaySession string `json:"relaySession"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

// Offer is sent by the coordinator to an exit when a client wants to connect.
// It carries the client's per-session ICE credentials + candidates so the exit
// can spin up a dedicated agent for that customer.
type Offer struct {
	SessionID    string      `json:"sessionID"`
	ClientPubKey string      `json:"clientPubKey"`
	ClientVPNIP  string      `json:"clientVPNIP"` // client's /32, for the exit's allowed_ips + routing
	Ufrag        string      `json:"ufrag"`
	Pwd          string      `json:"pwd"`
	Candidates   []Candidate `json:"candidates"`
}

// Answer is the exit's reply: the per-session creds + candidates it minted for
// that one client. The coordinator relays these to the client as a Punch.
type Answer struct {
	SessionID    string      `json:"sessionID"`
	ClientPubKey string      `json:"clientPubKey"`
	Ufrag        string      `json:"ufrag"`
	Pwd          string      `json:"pwd"`
	Candidates   []Candidate `json:"candidates"`
}
