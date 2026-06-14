package main

// RPN Direct coordinator — robust production version.
//
// Control channel: WSS  :8089/tcp
// STUN primary:         :3479/udp  (RFC 5389; public endpoint discovery)
// STUN secondary:       :3481/udp  (RFC 5780; NAT-type classification via dual-port)
// TURN relay:           :3480/udp  (WG-encrypted; last-resort when punch fails)
//
// Key design: coordinator introduces peers and triggers hole-punching; it is
// NEVER in the data path once a direct WG connection is up. TURN relay is only
// used when both ends are behind symmetric CGNAT with no other option.
//
// Added vs scaffold:
//   - TLS (WSS) via -tls-cert/-tls-key
//   - Persistent IP assignments (JSON state file, survives restarts)
//   - HMAC-SHA1 time-limited TURN credentials (RFC 5766 §10.2 long-term)
//   - Relay-first: send relay info immediately on connect so client has a
//     working path right away; upgrade to direct when punch succeeds
//   - Dual STUN ports for RFC 5780 NAT-behavior classification
//   - Rate limiting: max 10 hello/min per remote IP
//   - /exit/info: reads Pi's live CGNAT endpoint from wg show dump so the
//     Android client can dial Pi directly with zero VPS data-path involvement

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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

// ── persistent state ─────────────────────────────────────────────────────────

type diskState struct {
	IPs        map[string]string `json:"ips"`
	NextClient int               `json:"nextClient"`
	NextExit   int               `json:"nextExit"`
}

// ── peer ─────────────────────────────────────────────────────────────────────

type peer struct {
	info    PeerInfo
	network string
	conn    *websocket.Conn
	send    chan []byte
}

// ── rate limiter ──────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{windows: map[string][]time.Time{}}
}

func (r *rateLimiter) allow(key string, maxPerMin int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	w := r.windows[key]
	valid := w[:0]
	for _, t := range w {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= maxPerMin {
		r.windows[key] = valid
		return false
	}
	r.windows[key] = append(valid, now)
	return true
}

// ── hub ──────────────────────────────────────────────────────────────────────

type hub struct {
	mu      sync.Mutex
	peers   map[string]*peer  // pubKey -> peer
	ips     map[string]string // pubKey -> stable VPN /32
	codes   map[string]string // accessCode -> networkID ("" map = dev mode)
	clientN int
	exitN   int

	stunAddr   string // primary STUN endpoint advertised to peers
	stunAddr2  string // secondary STUN endpoint (RFC 5780 dual-port)
	relayAddr  string // TURN relay endpoint advertised to peers
	turnSecret string // HMAC-SHA1 secret for TURN credentials
	stateFile  string // path to persist IP assignments

	rl *rateLimiter
}

func newHub(codes map[string]string, stunAddr, stunAddr2, relayAddr, turnSecret, stateFile string) *hub {
	h := &hub{
		peers:      map[string]*peer{},
		ips:        map[string]string{},
		codes:      codes,
		clientN:    101,
		exitN:      2,
		stunAddr:   stunAddr,
		stunAddr2:  stunAddr2,
		relayAddr:  relayAddr,
		turnSecret: turnSecret,
		stateFile:  stateFile,
		rl:         newRateLimiter(),
	}
	h.loadState()
	return h
}

func (h *hub) loadState() {
	if h.stateFile == "" {
		return
	}
	data, err := os.ReadFile(h.stateFile)
	if err != nil {
		return
	}
	var s diskState
	if json.Unmarshal(data, &s) == nil && s.IPs != nil {
		h.ips = s.IPs
		if s.NextClient >= 101 {
			h.clientN = s.NextClient
		}
		if s.NextExit >= 2 {
			h.exitN = s.NextExit
		}
		log.Printf("state loaded: %d peers, nextClient=%d nextExit=%d", len(h.ips), h.clientN, h.exitN)
	}
}

func (h *hub) saveState() {
	if h.stateFile == "" {
		return
	}
	s := diskState{IPs: h.ips, NextClient: h.clientN, NextExit: h.exitN}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	tmp := h.stateFile + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		os.Rename(tmp, h.stateFile)
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
	h.saveState()
	return ip
}

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
		log.Printf("peer %s send buffer full — dropping", short(p.info.PubKey))
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

// ── TURN credentials ─────────────────────────────────────────────────────────

// turnCreds generates time-limited HMAC-SHA1 TURN credentials.
// username = "{expiry_unix}:{peer_short}", password = base64(HMAC-SHA1(secret, username)).
// The TURN AuthHandler re-derives the password from the secret; no per-peer state needed.
func (h *hub) turnCreds(peerKey string) (username, password string) {
	expiry := time.Now().Add(24 * time.Hour).Unix()
	username = fmt.Sprintf("%d:%s", expiry, short(peerKey))
	mac := hmac.New(sha1.New, []byte(h.turnSecret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	clientIP := remoteIP(r)
	if !h.rl.allow(clientIP, 10) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

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
		log.Printf("rejected hello from %s", clientIP)
		conn.Close()
		return
	}
	role := hello.Role
	if role != RoleExit {
		role = RoleClient
	}
	conn.SetReadDeadline(time.Time{})

	h.mu.Lock()
	// Clean replacement for reconnecting peers: close old conn, new send channel.
	if old, exists := h.peers[hello.PubKey]; exists {
		old.conn.Close()
		// writeLoop will exit when conn errors; don't close(old.send) here to avoid race.
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
		send:    make(chan []byte, 64),
	}
	h.peers[hello.PubKey] = p
	h.mu.Unlock()

	log.Printf("registered %s role=%s ip=%s network=%s from=%s", short(hello.PubKey), role, vpnIP, network, clientIP)

	welcome, _ := encode(TypeWelcome, Welcome{
		SelfIP:        vpnIP,
		NetworkID:     network,
		STUNEndpoint:  h.stunAddr,
		STUN2Endpoint: h.stunAddr2,
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
	session := pairKey(p.info.PubKey, target.info.PubKey)

	// RELAY FIRST — both peers get a working relay path immediately.
	// They can use it right away while hole-punching runs in the background.
	// This ensures the product always works on tap-one, even if NAT punch fails.
	pUser, pPass := h.turnCreds(p.info.PubKey)
	tUser, tPass := h.turnCreds(target.info.PubKey)
	pRelayMsg, _ := encode(TypeRelay, Relay{
		PeerPubKey: target.info.PubKey, RelaySession: session,
		Username: pUser, Password: pPass,
	})
	tRelayMsg, _ := encode(TypeRelay, Relay{
		PeerPubKey: p.info.PubKey, RelaySession: session,
		Username: tUser, Password: tPass,
	})
	h.trySend(p, pRelayMsg)
	h.trySend(target, tRelayMsg)

	// THEN PUNCH — trigger synchronized simultaneous-open to upgrade to direct.
	pToTarget, _ := encode(TypePunch, Punch{
		PeerPubKey: target.info.PubKey,
		Candidates: target.info.Candidates,
		AtUnixMs:   at,
	})
	targetToP, _ := encode(TypePunch, Punch{
		PeerPubKey: p.info.PubKey,
		Candidates: p.info.Candidates,
		AtUnixMs:   at,
	})
	h.trySend(p, pToTarget)
	h.trySend(target, targetToP)
	h.mu.Unlock()

	log.Printf("introduce %s <-> %s at=%d relay=%s...", short(p.info.PubKey), short(targetPubKey), at, session[:8])
}

func (h *hub) onResult(p *peer, res Result) {
	h.mu.Lock()
	p.info.DirectOK = res.OK && res.Via == "direct"
	h.mu.Unlock()
	if res.OK {
		log.Printf("path up %s->%s via=%s addr=%s", short(p.info.PubKey), short(res.PeerPubKey), res.Via, res.Addr)
	} else {
		// Relay path was already established in introduce(); just log.
		log.Printf("direct failed %s<->%s (relay already active)", short(p.info.PubKey), short(res.PeerPubKey))
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

// ── STUN server (RFC 5389) ────────────────────────────────────────────────────
// Two instances run: primary (:3479) and secondary (:3481).
// A client that compares its mapped address from both ports can detect whether
// its NAT maps the same public ip:port regardless of destination (endpoint-
// independent) or not (endpoint-dependent / symmetric). Symmetric NAT cannot
// be punched; the relay is used instead.

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

// ── TURN relay server (pion/turn) ─────────────────────────────────────────────
// Used only when direct punch fails. The relay forwards opaque UDP; WG already
// encrypts the payload so the relay sees nothing useful.

func runTURN(publicIP, listenAddr, secret string) {
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

	_, err = turn.NewServer(turn.ServerConfig{
		Realm: "rpndirect",
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			if secret == "" {
				// Dev mode: open relay (warn logged at startup).
				return turn.GenerateAuthKey(username, realm, username), true
			}
			// Verify time-limited HMAC-SHA1 credential.
			// username format: "{expiry_unix}:{peer_short}"
			parts := strings.SplitN(username, ":", 2)
			if len(parts) != 2 {
				return nil, false
			}
			expiry, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil || time.Now().Unix() > expiry {
				return nil, false
			}
			mac := hmac.New(sha1.New, []byte(secret))
			mac.Write([]byte(username))
			password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			return turn.GenerateAuthKey(username, realm, password), true
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
	log.Printf("TURN relay on %s (public %s)", listenAddr, publicIP)
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

func itoa(n int) string { return strconv.Itoa(n) }

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

// ── /exit/info ───────────────────────────────────────────────────────────────
// Returns the Pi exit node's live public endpoint as seen by the VPS kernel
// WireGuard (wg show wgd0 dump). The Android client fetches this to connect
// WireGuard directly to the Pi — VPS is not in the data path at all.

const piPubKey = "saTh5M1UOLIc7YzWhJqRYxtt5dzt/XebC37b/OgMh2U="

type exitInfoResponse struct {
	PubKey   string `json:"pubKey"`
	Endpoint string `json:"endpoint"` // "122.164.83.185:11855" — Pi's live CGNAT endpoint
}

func wgDumpEndpoint(iface, pubKey string) (string, bool) {
	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		if strings.TrimSpace(fields[0]) == pubKey {
			ep := strings.TrimSpace(fields[2])
			if ep != "" && ep != "(none)" {
				return ep, true
			}
		}
	}
	return "", false
}

func exitInfoHandler(wgIface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ep, ok := wgDumpEndpoint(wgIface, piPubKey)
		if !ok {
			http.Error(w, `{"error":"pi endpoint not available"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exitInfoResponse{PubKey: piPubKey, Endpoint: ep})
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	httpAddr   := flag.String("http",           ":8089",                "control-channel listen address")
	tlsCert    := flag.String("tls-cert",       "",                     "TLS certificate file (enables WSS)")
	tlsKey     := flag.String("tls-key",        "",                     "TLS private key file")
	stunAddr   := flag.String("stun",           ":3479",                "primary STUN UDP listen address")
	stun2Addr  := flag.String("stun2",          ":3481",                "secondary STUN UDP (RFC 5780 dual-port)")
	turnAddr   := flag.String("turn",           ":3480",                "TURN relay UDP listen address")
	publicIP   := flag.String("public-ip",      "65.20.80.3",           "VPS public IP (TURN relay generator)")
	stunPub    := flag.String("stun-public",    "65.20.80.3:3479",      "advertised primary STUN endpoint")
	stun2Pub   := flag.String("stun2-public",   "65.20.80.3:3481",      "advertised secondary STUN endpoint (RFC 5780)")
	relayPub   := flag.String("relay-public",   "65.20.80.3:3480",      "advertised TURN relay endpoint")
	turnSecret := flag.String("turn-secret",    "",                     "HMAC-SHA1 secret for TURN credentials (required in prod)")
	codesStr   := flag.String("codes",          "",                     `access codes "code:network,..."; empty = dev mode`)
	stateFile  := flag.String("state-file",     "/opt/rpn-coord/state.json", "persistent IP assignment state")
	wgIface    := flag.String("wg-iface",       "wgd0",                 "WireGuard interface for /exit/info endpoint")
	flag.Parse()

	if *turnSecret == "" {
		log.Printf("WARNING: -turn-secret not set — TURN relay is open (dev only, not for production)")
	}

	codes := parseCodes(*codesStr)
	if len(codes) == 0 {
		log.Printf("WARNING: DEV MODE — any access code accepted")
	}

	h := newHub(codes, *stunPub, *stun2Pub, *relayPub, *turnSecret, *stateFile)

	go runSTUN(*stunAddr)
	go runSTUN(*stun2Addr)
	go runTURN(*publicIP, *turnAddr, *turnSecret)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.handleWS)
	mux.HandleFunc("/exit/info", exitInfoHandler(*wgIface))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		n := len(h.peers)
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"peers":%d}`, n)
	})

	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("coordinator (WSS/TLS) on %s", *httpAddr)
		log.Fatal(http.ListenAndServeTLS(*httpAddr, *tlsCert, *tlsKey, mux))
	} else {
		log.Printf("coordinator (WS, no TLS) on %s — set -tls-cert/-tls-key for production", *httpAddr)
		log.Fatal(http.ListenAndServe(*httpAddr, mux))
	}
}
