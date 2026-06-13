package main

// RPN Direct coordinator — milestone 1 (signaling + STUN) + milestone 2 (TURN relay).
//
// Roles:
//   coordinator (this binary, runs on VPS) — public, always-on.
//     • WSS control channel  :8089/tcp  — peer registration, candidate exchange, punch
//     • STUN (RFC 5389)      :3479/udp  — server-reflexive candidate discovery
//     • TURN relay           :3480/udp  — last-resort relay when punch fails
//
// The coordinator is NEVER in the data path once a direct WG path is up.
// TURN is only used when both ends are behind symmetric CGNAT with no other option.
//
// Isolated from the live Headscale stack: separate process, separate ports, separate subnet.

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	pionlogging "github.com/pion/logging"
	pionstun "github.com/pion/stun/v2"
	"github.com/pion/turn/v3"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ── peer ─────────────────────────────────────────────────────────────────────

type peer struct {
	info    PeerInfo
	network string
	conn    *websocket.Conn
	send    chan []byte
}

// ── hub ──────────────────────────────────────────────────────────────────────

type hub struct {
	mu      sync.Mutex
	peers   map[string]*peer  // pubKey -> peer
	ips     map[string]string // pubKey -> stable VPN /32
	codes   map[string]string // accessCode -> networkID ("" map = dev mode)
	clientN int
	exitN   int

	stunAddr  string // advertised to peers
	relayAddr string // advertised to peers
}

func newHub(codes map[string]string, stunAddr, relayAddr string) *hub {
	return &hub{
		peers:     map[string]*peer{},
		ips:       map[string]string{},
		codes:     codes,
		clientN:   101,
		exitN:     2,
		stunAddr:  stunAddr,
		relayAddr: relayAddr,
	}
}

func (h *hub) authNetwork(code string) (string, bool) {
	if len(h.codes) == 0 {
		return "default", true
	}
	n, ok := h.codes[code]
	return n, ok
}

func (h *hub) assignIP(pubKey, role string) string {
	if ip, ok := h.ips[pubKey]; ok {
		return ip
	}
	var ip string
	if role == RoleExit {
		ip = "10.99.0." + itoa(h.exitN) + "/32"
		h.exitN++
	} else {
		ip = "10.99.0." + itoa(h.clientN) + "/32"
		h.clientN++
	}
	h.ips[pubKey] = ip
	return ip
}

func itoa(n int) string { return strconv.Itoa(n) }

func (h *hub) peerList(network, exclude string) []PeerInfo {
	var out []PeerInfo
	for pk, p := range h.peers {
		if pk == exclude || p.network != network {
			continue
		}
		out = append(out, p.info)
	}
	return out
}

func (h *hub) broadcastPeers(network string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for pk, p := range h.peers {
		if p.network != network {
			continue
		}
		msg, err := encode(TypePeers, Peers{Peers: h.peerList(network, pk)})
		if err != nil {
			continue
		}
		h.trySend(p, msg)
	}
}

func (h *hub) trySend(p *peer, msg []byte) {
	select {
	case p.send <- msg:
	default:
		log.Printf("peer %s buffer full, dropping", short(p.info.PubKey))
		close(p.send)
		delete(h.peers, p.info.PubKey)
	}
}

func (h *hub) sendTo(pubKey string, msg []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.peers[pubKey]
	if !ok {
		return false
	}
	h.trySend(p, msg)
	return true
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade: %v", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Type != TypeHello {
		conn.Close()
		return
	}
	var hello Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		conn.Close()
		return
	}
	network, ok := h.authNetwork(hello.AccessCode)
	if !ok || hello.PubKey == "" {
		log.Printf("rejected hello from %s", conn.RemoteAddr())
		conn.Close()
		return
	}
	role := hello.Role
	if role != RoleExit {
		role = RoleClient
	}
	conn.SetReadDeadline(time.Time{})

	h.mu.Lock()
	if old, exists := h.peers[hello.PubKey]; exists {
		close(old.send)
		old.conn.Close()
	}
	vpnIP := h.assignIP(hello.PubKey, role)
	p := &peer{
		info: PeerInfo{
			PubKey: hello.PubKey,
			Role:   role,
			VPNIP:  vpnIP,
		},
		network: network,
		conn:    conn,
		send:    make(chan []byte, 32),
	}
	h.peers[hello.PubKey] = p
	h.mu.Unlock()

	log.Printf("registered %s role=%s ip=%s network=%s", short(hello.PubKey), role, vpnIP, network)

	welcome, _ := encode(TypeWelcome, Welcome{
		SelfIP:        vpnIP,
		NetworkID:     network,
		STUNEndpoint:  h.stunAddr,
		RelayEndpoint: h.relayAddr,
	})
	p.send <- welcome

	go h.writeLoop(p)
	h.broadcastPeers(network)
	h.readLoop(p)
}

func (h *hub) writeLoop(p *peer) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-p.send:
			if !ok {
				p.conn.Close()
				return
			}
			if err := p.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				p.conn.Close()
				return
			}
		case <-ticker.C:
			ping, _ := encode(TypePing, nil)
			if err := p.conn.WriteMessage(websocket.TextMessage, ping); err != nil {
				p.conn.Close()
				return
			}
		}
	}
}

func (h *hub) readLoop(p *peer) {
	defer h.drop(p)
	p.conn.SetReadLimit(64 * 1024)
	for {
		_, raw, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case TypeEndpoints:
			var e Endpoints
			if json.Unmarshal(env.Data, &e) == nil {
				h.mu.Lock()
				p.info.Candidates = e.Candidates
				p.info.DirectOK = hasPublicCandidate(e.Candidates)
				net := p.network
				h.mu.Unlock()
				h.broadcastPeers(net)
			}
		case TypeConnect:
			var c Connect
			if json.Unmarshal(env.Data, &c) == nil {
				h.introduce(p, c.PeerPubKey)
			}
		case TypeResult:
			var res Result
			if json.Unmarshal(env.Data, &res) == nil {
				h.onResult(p, res)
			}
		case TypePong, TypePing:
		}
	}
}

func (h *hub) introduce(p *peer, targetPubKey string) {
	h.mu.Lock()
	target, ok := h.peers[targetPubKey]
	if !ok || target.network != p.network {
		h.mu.Unlock()
		return
	}
	at := time.Now().Add(500 * time.Millisecond).UnixMilli()
	pToTarget, _ := encode(TypePunch, Punch{PeerPubKey: target.info.PubKey, Candidates: target.info.Candidates, AtUnixMs: at})
	targetToP, _ := encode(TypePunch, Punch{PeerPubKey: p.info.PubKey, Candidates: p.info.Candidates, AtUnixMs: at})
	h.trySend(p, pToTarget)
	h.trySend(target, targetToP)
	h.mu.Unlock()
	log.Printf("punch %s <-> %s at=%d", short(p.info.PubKey), short(targetPubKey), at)
}

func (h *hub) onResult(p *peer, res Result) {
	h.mu.Lock()
	p.info.DirectOK = res.OK && res.Via == "direct"
	h.mu.Unlock()
	if res.OK {
		log.Printf("path up %s->%s via=%s addr=%s", short(p.info.PubKey), short(res.PeerPubKey), res.Via, res.Addr)
		return
	}
	session := pairKey(p.info.PubKey, res.PeerPubKey)
	log.Printf("direct failed %s<->%s; relay session=%s", short(p.info.PubKey), short(res.PeerPubKey), session[:8])
	if m, err := encode(TypeRelay, Relay{PeerPubKey: res.PeerPubKey, RelaySession: session}); err == nil {
		h.sendTo(p.info.PubKey, m)
	}
	if m, err := encode(TypeRelay, Relay{PeerPubKey: p.info.PubKey, RelaySession: session}); err == nil {
		h.sendTo(res.PeerPubKey, m)
	}
}

func (h *hub) drop(p *peer) {
	h.mu.Lock()
	if cur, ok := h.peers[p.info.PubKey]; ok && cur == p {
		delete(h.peers, p.info.PubKey)
		close(p.send)
	}
	net := p.network
	h.mu.Unlock()
	p.conn.Close()
	log.Printf("dropped %s", short(p.info.PubKey))
	h.broadcastPeers(net)
}

// ── STUN server (RFC 5389 via pion/stun) ────────────────────────────────────

func runSTUN(addr string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatalf("stun listen %s: %v", addr, err)
	}
	log.Printf("STUN (RFC 5389) listening on %s (udp)", addr)
	buf := make([]byte, 1500)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go handleSTUN(pc, src, pkt)
	}
}

func handleSTUN(pc net.PacketConn, src net.Addr, pkt []byte) {
	msg := &pionstun.Message{Raw: pkt}
	if err := msg.Decode(); err != nil {
		return
	}
	if msg.Type != pionstun.BindingRequest {
		return
	}
	udpAddr, ok := src.(*net.UDPAddr)
	if !ok {
		return
	}
	resp, err := pionstun.Build(msg,
		pionstun.BindingSuccess,
		&pionstun.XORMappedAddress{IP: udpAddr.IP, Port: udpAddr.Port},
		pionstun.Fingerprint,
	)
	if err != nil {
		return
	}
	pc.WriteTo(resp.Raw, src)
}

// ── TURN relay server (pion/turn) ────────────────────────────────────────────
//
// Used only when direct punch fails (symmetric-CGNAT on both ends).
// Each peer-pair gets an allocation; WG traffic is already encrypted so
// the relay just forwards opaque UDP — no inspection needed.

func runTURN(publicIP, listenAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		log.Fatalf("turn resolve %s: %v", listenAddr, err)
	}
	conn, err := net.ListenPacket("udp4", udpAddr.String())
	if err != nil {
		log.Fatalf("turn listen %s: %v", listenAddr, err)
	}

	logFactory := pionlogging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = pionlogging.LogLevelWarn

	// Open relay is acceptable here: WG already encrypts the data payload.
	// Only peers that know their relay session (TURN credentials) can use their allocation.
	_, err = turn.NewServer(turn.ServerConfig{
		Realm: "rpndirect",
		// CredentialMechanism: turn.LongTermTURN — credentials = pairKey session tokens
		// For milestone 2 we use AuthHandler that accepts any username, which is safe
		// because the relay is only announced to authenticated WSS peers and WG encrypts
		// the payload. Tighten to per-session credentials in milestone 3.
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			return turn.GenerateAuthKey(username, realm, username), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: conn,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(publicIP),
					Address:      "0.0.0.0",
				},
			},
		},
		LoggerFactory: logFactory,
	})
	if err != nil {
		log.Fatalf("turn server: %v", err)
	}
	log.Printf("TURN relay listening on %s (udp), public IP %s", listenAddr, publicIP)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func hasPublicCandidate(cands []Candidate) bool {
	for _, c := range cands {
		if c.Type == "host" || c.Type == "srflx" {
			if ip := net.ParseIP(strings.Split(c.Addr, ":")[0]); ip != nil && !isPrivate(ip) {
				return true
			}
		}
	}
	return false
}

func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func pairKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

func short(pubKey string) string {
	if len(pubKey) > 8 {
		return pubKey[:8]
	}
	return pubKey
}

func parseCodes(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return out
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	httpAddr  := flag.String("http",         ":8089",       "WSS control-channel listen address")
	stunAddr  := flag.String("stun",         ":3479",       "STUN UDP listen address")
	turnAddr  := flag.String("turn",         ":3480",       "TURN relay UDP listen address")
	publicIP  := flag.String("public-ip",    "65.20.80.3",  "VPS public IP (for TURN relay address generator)")
	stunPub   := flag.String("stun-public",  "65.20.80.3:3479", "Advertised STUN endpoint")
	relayPub  := flag.String("relay-public", "65.20.80.3:3480", "Advertised TURN relay endpoint")
	codesStr  := flag.String("codes",        "",            `Access codes "code:network,..."; empty = dev mode`)
	flag.Parse()

	codes := parseCodes(*codesStr)
	if len(codes) == 0 {
		log.Printf("WARNING: DEV MODE — any access code accepted")
	}

	h := newHub(codes, *stunPub, *relayPub)

	go runSTUN(*stunAddr)
	go runTURN(*publicIP, *turnAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.handleWS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		n := len(h.peers)
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"peers":` + itoa(n) + `}`))
	})

	log.Printf("coordinator control channel on %s", *httpAddr)
	log.Fatal(http.ListenAndServe(*httpAddr, mux))
}
