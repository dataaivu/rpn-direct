package main

// RPN Direct coordinator — infinitely scalable fleet edition.
//
// Architecture: VPS carries ZERO data. Each Pi is its own WireGuard hub.
// Customers connect directly to their assigned Pi. The coordinator's only jobs:
//   1. Pi fleet registry (register, heartbeat, liveness)
//   2. Customer assignment (access-code → least-loaded Pi → WG config)
//   3. Real-time signaling (WSS: punch, STUN candidates, relay fallback)
//
// Adding Pi #1001 adds capacity with zero VPS bandwidth cost.
//
// Ports:
//   :8089/tcp  WSS control channel (punch + candidate exchange)
//   :3479/udp  STUN primary  (RFC 5389)
//   :3481/udp  STUN secondary (RFC 5780 dual-port NAT classification)
//   :3480/udp  TURN relay    (last-resort only)

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ── signaling hub (WSS) ───────────────────────────────────────────────────────

type wsPeer struct {
	info    PeerInfo
	network string
	conn    *websocket.Conn
	send    chan []byte
}

type sigHub struct {
	mu    sync.Mutex
	peers map[string]*wsPeer // pubKey -> wsPeer

	stunAddr   string
	stunAddr2  string
	relayAddr  string
	turnSecret string
	rl         *rateLimiter
	store      *store
	fleetToken string
	adminToken string
}

func newSigHub(db *store, stunAddr, stunAddr2, relayAddr, turnSecret, fleetToken, adminToken string) *sigHub {
	return &sigHub{
		peers:      map[string]*wsPeer{},
		stunAddr:   stunAddr,
		stunAddr2:  stunAddr2,
		relayAddr:  relayAddr,
		turnSecret: turnSecret,
		rl:         newRateLimiter(),
		store:      db,
		fleetToken: fleetToken,
		adminToken: adminToken,
	}
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

// ── TURN credentials ─────────────────────────────────────────────────────────

func (h *sigHub) turnCreds(peerKey string) (username, password string) {
	expiry := time.Now().Add(24 * time.Hour).Unix()
	username = fmt.Sprintf("%d:%s", expiry, short(peerKey))
	mac := hmac.New(sha1.New, []byte(h.turnSecret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

// ── WSS handler ───────────────────────────────────────────────────────────────

func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (h *sigHub) handleWS(w http.ResponseWriter, r *http.Request) {
	clientIP := remoteIP(r)
	if !h.rl.allow(clientIP, 10) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
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
	if err := json.Unmarshal(env.Data, &hello); err != nil || hello.PubKey == "" {
		conn.Close()
		return
	}

	// Validate: access code or fleet token
	var network, role string
	if hello.Role == RoleExit && hello.AccessCode == h.fleetToken {
		network = "fleet"
		role = RoleExit
	} else {
		// Customer: look up access code in DB
		net, _, ok := h.store.validateCode(hello.AccessCode)
		if !ok {
			log.Printf("ws: rejected %s from %s (bad code)", short(hello.PubKey), clientIP)
			conn.Close()
			return
		}
		network = net
		role = RoleClient
	}
	conn.SetReadDeadline(time.Time{})

	// Look up or create VPN IP from DB
	var vpnIP string
	if role == RoleExit {
		p, _ := h.store.piByPubKey(hello.PubKey)
		if p != nil {
			vpnIP = p.VPNIP
		} else {
			vpnIP = "0.0.0.0/32" // Pi registers via REST; WSS just signals
		}
	} else {
		c, _ := h.store.customerByID(hello.AccessCode)
		if c != nil {
			vpnIP = c.VPNIP
		}
	}

	h.mu.Lock()
	if old, exists := h.peers[hello.PubKey]; exists {
		old.conn.Close()
	}
	p := &wsPeer{
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

	log.Printf("ws: registered %s role=%s net=%s", short(hello.PubKey), role, network)

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

func (h *sigHub) writeLoop(p *wsPeer) {
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

func (h *sigHub) readLoop(p *wsPeer) {
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
				p.info.Ufrag = e.Ufrag
				p.info.Pwd = e.Pwd
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

func (h *sigHub) broadcastPeers(network string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var list []PeerInfo
	for _, p := range h.peers {
		if p.network == network {
			list = append(list, p.info)
		}
	}
	for _, p := range h.peers {
		if p.network != network {
			continue
		}
		filtered := make([]PeerInfo, 0, len(list))
		for _, pi := range list {
			if pi.PubKey != p.info.PubKey {
				filtered = append(filtered, pi)
			}
		}
		msg, _ := encode(TypePeers, Peers{Peers: filtered})
		h.trySend(p, msg)
	}
}

func (h *sigHub) trySend(p *wsPeer, msg []byte) {
	select {
	case p.send <- msg:
	default:
		close(p.send)
		delete(h.peers, p.info.PubKey)
	}
}

func (h *sigHub) introduce(p *wsPeer, targetPubKey string) {
	h.mu.Lock()
	target, ok := h.peers[targetPubKey]
	if !ok || target.network != p.network {
		h.mu.Unlock()
		return
	}
	at := time.Now().Add(500 * time.Millisecond).UnixMilli()
	session := pairKey(p.info.PubKey, target.info.PubKey)

	pUser, pPass := h.turnCreds(p.info.PubKey)
	tUser, tPass := h.turnCreds(target.info.PubKey)
	pRelay, _ := encode(TypeRelay, Relay{PeerPubKey: target.info.PubKey, RelaySession: session, Username: pUser, Password: pPass})
	tRelay, _ := encode(TypeRelay, Relay{PeerPubKey: p.info.PubKey, RelaySession: session, Username: tUser, Password: tPass})
	h.trySend(p, pRelay)
	h.trySend(target, tRelay)

	pPunch, _ := encode(TypePunch, Punch{PeerPubKey: target.info.PubKey, Candidates: target.info.Candidates, AtUnixMs: at, Ufrag: target.info.Ufrag, Pwd: target.info.Pwd})
	tPunch, _ := encode(TypePunch, Punch{PeerPubKey: p.info.PubKey, Candidates: p.info.Candidates, AtUnixMs: at, Ufrag: p.info.Ufrag, Pwd: p.info.Pwd})
	h.trySend(p, pPunch)
	h.trySend(target, tPunch)
	h.mu.Unlock()
}

func (h *sigHub) onResult(p *wsPeer, res Result) {
	h.mu.Lock()
	p.info.DirectOK = res.OK && res.Via == "direct"
	h.mu.Unlock()
	log.Printf("path %s->%s via=%s ok=%v", short(p.info.PubKey), short(res.PeerPubKey), res.Via, res.OK)
}

func (h *sigHub) drop(p *wsPeer) {
	h.mu.Lock()
	if cur, ok := h.peers[p.info.PubKey]; ok && cur == p {
		delete(h.peers, p.info.PubKey)
		close(p.send)
	}
	net := p.network
	h.mu.Unlock()
	p.conn.Close()
	h.broadcastPeers(net)
}

// ── REST API ──────────────────────────────────────────────────────────────────

// POST /pi/register
// Pi first-boot registration. Returns VPN IP + WG listen config.
// Body: { fleet_token, serial, pubkey, name?, location? }
func (h *sigHub) handlePiRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FleetToken string `json:"fleet_token"`
		Serial     string `json:"serial"`
		PubKey     string `json:"pubkey"`
		Name       string `json:"name"`
		Location   string `json:"location"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.FleetToken != h.fleetToken || req.Serial == "" || req.PubKey == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	existing, _ := h.store.piByID(req.Serial)
	var vpnIP string
	if existing != nil {
		vpnIP = existing.VPNIP
	} else {
		ip, err := h.store.nextPiIP()
		if err != nil {
			http.Error(w, "no IPs available", http.StatusServiceUnavailable)
			return
		}
		vpnIP = ip
	}

	if err := h.store.upsertPi(req.Serial, req.PubKey, vpnIP, req.Name, req.Location); err != nil {
		log.Printf("upsertPi %s: %v", req.Serial, err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	log.Printf("pi registered: serial=%s pubkey=%s vpn=%s", req.Serial, short(req.PubKey), vpnIP)
	jsonOK(w, map[string]any{
		"pi_id":          req.Serial,
		"vpn_ip":         vpnIP,
		"wg_listen_port": 51821,
		"coordinator":    "ws://" + r.Host + "/ws",
	})
}

// POST /pi/heartbeat
// Pi periodic health report (every 30s). Returns current customer list for peer sync.
// Body: { pi_id, pubkey, stun_ep, customers }
func (h *sigHub) handlePiHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PiID      string `json:"pi_id"`
		PubKey    string `json:"pubkey"`
		StunEP    string `json:"stun_ep"`
		Customers int    `json:"customers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil || req.PiID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if err := h.store.piHeartbeat(req.PiID, req.StunEP, req.Customers); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Return current customer list so Pi can sync its WG peers.
	customers, _ := h.store.customersByPi(req.PiID)
	type custOut struct {
		PubKey   string `json:"pubkey"`
		VPNIP    string `json:"vpn_ip"`
		Endpoint string `json:"endpoint"` // so the Pi can set the peer endpoint and punch back
	}
	out := make([]custOut, 0, len(customers))
	for _, c := range customers {
		if c.PubKey != "" {
			out = append(out, custOut{PubKey: c.PubKey, VPNIP: c.VPNIP, Endpoint: c.Endpoint})
		}
	}
	jsonOK(w, map[string]any{"customers": out})
}

// POST /customer/register
// Customer app calls this with their access code + WG pubkey.
// Returns WG config pointing directly at the assigned Pi (no VPS in data path).
// Body: { access_code, pubkey }
func (h *sigHub) handleCustomerRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AccessCode string `json:"access_code"`
		PubKey     string `json:"pubkey"`
		Endpoint   string `json:"endpoint"` // customer's STUN-mapped ip:port, for the Pi to punch back
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil || req.AccessCode == "" || req.PubKey == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.rl.allow("customer:"+req.AccessCode, 5) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	_, usedBy, ok := h.store.validateCode(req.AccessCode)
	if !ok {
		http.Error(w, "invalid access code", http.StatusUnauthorized)
		return
	}

	// Existing customer re-registering (new device / new key)
	existing, _ := h.store.customerByID(req.AccessCode)
	var vpnIP, piID string
	var pi *PiRecord

	if existing != nil {
		vpnIP = existing.VPNIP
		piID = existing.PiID
		if piID != "" {
			pi, _ = h.store.piByID(piID)
		}
	}

	// Assign a Pi if not yet assigned or Pi went inactive
	if pi == nil || pi.Active == 0 {
		pi, _ = h.store.leastLoadedPi()
		if pi == nil {
			http.Error(w, "no Pi available — check back soon", http.StatusServiceUnavailable)
			return
		}
		piID = pi.ID
	}

	if vpnIP == "" {
		ip, err := h.store.nextCustomerIP()
		if err != nil {
			http.Error(w, "no IPs available", http.StatusServiceUnavailable)
			return
		}
		vpnIP = ip
	}
	_ = usedBy

	if err := h.store.upsertCustomer(req.AccessCode, req.PubKey, vpnIP, piID, req.Endpoint); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	h.store.bindCode(req.AccessCode, req.AccessCode)

	// Build WG config: customer dials Pi directly, VPS not in data path.
	wgConf := fmt.Sprintf(`[Interface]
PrivateKey = REPLACE_WITH_YOUR_PRIVATE_KEY
Address = %s
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, stripCIDR(vpnIP)+"/32", pi.PubKey, pi.StunEP)

	log.Printf("customer registered: code=%s pubkey=%s vpn=%s pi=%s", req.AccessCode, short(req.PubKey), vpnIP, pi.ID)
	jsonOK(w, map[string]any{
		"vpn_ip":      vpnIP,
		"pi_id":       pi.ID,
		"pi_pubkey":   pi.PubKey,
		"pi_endpoint": pi.StunEP,
		"wg_config":   wgConf,
	})
}

// ── admin API ─────────────────────────────────────────────────────────────────

func (h *sigHub) adminAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.TrimPrefix(auth, "Bearer ") == h.adminToken
}

// GET /admin/pis
func (h *sigHub) handleAdminPis(w http.ResponseWriter, r *http.Request) {
	if !h.adminAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pis, err := h.store.listPis()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]any{"pis": pis, "count": len(pis)})
}

// POST /admin/codes  — create access codes
// Body: { codes: ["ABC123", "DEF456"], network: "default" }
func (h *sigHub) handleAdminCodes(w http.ResponseWriter, r *http.Request) {
	if !h.adminAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Codes   []string `json:"codes"`
		Network string   `json:"network"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Network == "" {
		req.Network = "default"
	}
	for _, code := range req.Codes {
		h.store.insertCode(code, req.Network)
	}
	jsonOK(w, map[string]any{"inserted": len(req.Codes)})
}

// GET /admin/customers?pi_id=xxx
func (h *sigHub) handleAdminCustomers(w http.ResponseWriter, r *http.Request) {
	if !h.adminAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	piID := r.URL.Query().Get("pi_id")
	var customers []CustomerRecord
	var err error
	if piID != "" {
		customers, err = h.store.customersByPi(piID)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]any{"customers": customers, "count": len(customers)})
}

// ── /exit/info (backward compat) ─────────────────────────────────────────────
// Returns the Pi exit node's live endpoint from wg show dump.

const piPubKey = "saTh5M1UOLIc7YzWhJqRYxtt5dzt/XebC37b/OgMh2U="

type exitInfoResponse struct {
	PubKey   string `json:"pubKey"`
	Endpoint string `json:"endpoint"`
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

// ── STUN server ───────────────────────────────────────────────────────────────

func runSTUN(addr string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatalf("stun listen %s: %v", addr, err)
	}
	log.Printf("STUN listening on %s (udp)", addr)
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

// ── TURN relay ────────────────────────────────────────────────────────────────

func runTURN(publicIP, listenAddr, secret string) {
	udpAddr, _ := net.ResolveUDPAddr("udp4", listenAddr)
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
				return turn.GenerateAuthKey(username, realm, username), true
			}
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
			pw := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			return turn.GenerateAuthKey(username, realm, pw), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(publicIP),
				Address:      "0.0.0.0",
			},
		}},
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

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func stripCIDR(ip string) string {
	if idx := strings.IndexByte(ip, '/'); idx >= 0 {
		return ip[:idx]
	}
	return ip
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func itoa(n int) string { return strconv.Itoa(n) }

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	httpAddr    := flag.String("http",           ":8089",                "control-channel listen address")
	tlsCert     := flag.String("tls-cert",       "",                     "TLS certificate file (enables WSS/HTTPS)")
	tlsKey      := flag.String("tls-key",        "",                     "TLS private key file")
	stunAddr    := flag.String("stun",           ":3479",                "primary STUN UDP listen address")
	stun2Addr   := flag.String("stun2",          ":3481",                "secondary STUN UDP (RFC 5780 dual-port)")
	turnAddr    := flag.String("turn",           ":3480",                "TURN relay UDP listen address")
	publicIP    := flag.String("public-ip",      "65.20.80.3",           "VPS public IP")
	stunPub     := flag.String("stun-public",    "65.20.80.3:3479",      "advertised primary STUN endpoint")
	stun2Pub    := flag.String("stun2-public",   "65.20.80.3:3481",      "advertised secondary STUN endpoint")
	relayPub    := flag.String("relay-public",   "65.20.80.3:3480",      "advertised TURN relay endpoint")
	turnSecret  := flag.String("turn-secret",    "",                     "HMAC-SHA1 secret for TURN credentials")
	fleetToken  := flag.String("fleet-token",    "",                     "shared secret baked into Pi SD card images")
	adminToken  := flag.String("admin-token",    "",                     "admin API bearer token")
	dbPath      := flag.String("db",             "/opt/rpn-coord/rpn.db","SQLite database path")
	wgIface     := flag.String("wg-iface",       "wgd0",                 "WireGuard interface for /exit/info")
	flag.Parse()

	if *fleetToken == "" {
		log.Printf("WARNING: -fleet-token not set — Pi registration disabled")
	}
	if *adminToken == "" {
		log.Printf("WARNING: -admin-token not set — admin API open")
	}
	if *turnSecret == "" {
		log.Printf("WARNING: -turn-secret not set — TURN relay is open (dev only)")
	}

	db, err := openStore(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}

	h := newSigHub(db, *stunPub, *stun2Pub, *relayPub, *turnSecret, *fleetToken, *adminToken)

	go runSTUN(*stunAddr)
	go runSTUN(*stun2Addr)
	go runTURN(*publicIP, *turnAddr, *turnSecret)

	mux := http.NewServeMux()
	// WSS signaling
	mux.HandleFunc("/ws", h.handleWS)
	// Pi fleet
	mux.HandleFunc("/pi/register",  h.handlePiRegister)
	mux.HandleFunc("/pi/heartbeat", h.handlePiHeartbeat)
	// Customer
	mux.HandleFunc("/customer/register", h.handleCustomerRegister)
	// Admin
	mux.HandleFunc("/admin/pis",       h.handleAdminPis)
	mux.HandleFunc("/admin/customers", h.handleAdminCustomers)
	mux.HandleFunc("/admin/codes",     h.handleAdminCodes)
	// Backward compat
	mux.HandleFunc("/exit/info", exitInfoHandler(*wgIface))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		n := len(h.peers)
		h.mu.Unlock()
		fmt.Fprintf(w, `{"ok":true,"ws_peers":%d}`, n)
	})

	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("coordinator (HTTPS/WSS) on %s", *httpAddr)
		log.Fatal(http.ListenAndServeTLS(*httpAddr, *tlsCert, *tlsKey, mux))
	} else {
		log.Printf("coordinator (HTTP/WS, no TLS) on %s", *httpAddr)
		log.Fatal(http.ListenAndServe(*httpAddr, mux))
	}
}
