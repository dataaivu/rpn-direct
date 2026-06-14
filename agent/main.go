package main

// RPN Direct — Pi exit-node agent.
//
// Runs on the Raspberry Pi (ARMv7). Connects to the coordinator as role=exit,
// reports its own ICE candidates (host + srflx) so the coordinator can include
// them in the peers broadcast, and syncs the live client peer list into the
// local kernel WireGuard interface (wgd0) via the `wg` CLI tool.
//
// When a new client peer is added with persistent-keepalive=5, kernel WireGuard
// immediately initiates a handshake → keepalive packet → opens the CGNAT
// mapping for that client's IP. The coordinator's /exit/info endpoint then
// serves Pi's current CGNAT endpoint (read from wgd0 by the VPS coordinator),
// and the Android client can connect WireGuard directly to the Pi.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	pionstun "github.com/pion/stun/v2"
)

// ── minimal wire types (mirrors coordinator/protocol.go) ─────────────────────

const (
	typeHello     = "hello"
	typeWelcome   = "welcome"
	typePeers     = "peers"
	typeEndpoints = "endpoints"
	typePing      = "ping"
	typePong      = "pong"
)

type envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type helloMsg struct {
	AccessCode string `json:"accessCode"`
	PubKey     string `json:"pubKey"`
	Role       string `json:"role"`
	Name       string `json:"name"`
}

type welcomeMsg struct {
	SelfIP       string `json:"selfIP"`
	STUNEndpoint string `json:"stunEndpoint"`
}

type candidate struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

type endpointsMsg struct {
	Candidates []candidate `json:"candidates"`
}

type peerInfo struct {
	PubKey string `json:"pubKey"`
	Role   string `json:"role"`
	VPNIP  string `json:"vpnIP"`
}

type peersMsg struct {
	Peers []peerInfo `json:"peers"`
}

func encode(t string, v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Type: t, Data: raw})
}

// ── backoff ───────────────────────────────────────────────────────────────────

type backoff struct {
	attempt int
	base    time.Duration
	max     time.Duration
}

func newBackoff() *backoff {
	return &backoff{base: 2 * time.Second, max: 60 * time.Second}
}

func (b *backoff) next() time.Duration {
	d := b.base
	for i := 0; i < b.attempt; i++ {
		d *= 2
		if d > b.max {
			d = b.max
			break
		}
	}
	// add up to 20% jitter
	jitter := time.Duration(rand.Int63n(int64(d) / 5))
	b.attempt++
	return d + jitter
}

func (b *backoff) reset() { b.attempt = 0 }

// ── STUN candidate discovery ──────────────────────────────────────────────────

// gatherCandidates collects the local host addresses and the srflx (server-
// reflexive) address by sending a STUN binding request to the coordinator's
// STUN endpoint. Returns all candidates; caller sends them as TypeEndpoints.
func gatherCandidates(stunEndpoint string) []candidate {
	var cands []candidate

	// Host candidates: all non-loopback, non-link-local IPv4 addresses.
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				// Skip WireGuard tunnel and other VPN addresses.
				if ip4[0] == 10 {
					continue
				}
				cands = append(cands, candidate{Type: "host", Addr: fmt.Sprintf("%s:0", ip4.String())})
			}
		}
	}

	// Server-reflexive (srflx) candidate via STUN binding request.
	if stunEndpoint != "" {
		if srflx, ok := stunSRFLX(stunEndpoint); ok {
			cands = append(cands, candidate{Type: "srflx", Addr: srflx})
		}
	}

	return cands
}

// stunSRFLX sends a STUN binding request and returns the XOR-MAPPED-ADDRESS.
func stunSRFLX(serverAddr string) (string, bool) {
	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		log.Printf("stun dial %s: %v", serverAddr, err)
		return "", false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, err := pionstun.Build(pionstun.TransactionID, pionstun.BindingRequest)
	if err != nil {
		return "", false
	}
	if _, err := conn.Write(req.Raw); err != nil {
		return "", false
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("stun read: %v", err)
		return "", false
	}

	resp := &pionstun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return "", false
	}
	var xorAddr pionstun.XORMappedAddress
	if err := xorAddr.GetFrom(resp); err != nil {
		return "", false
	}
	srflx := fmt.Sprintf("%s:%d", xorAddr.IP.String(), xorAddr.Port)
	log.Printf("srflx candidate: %s", srflx)
	return srflx, true
}

// ── wg helpers ────────────────────────────────────────────────────────────────

func wgPubKey(iface string) (string, error) {
	out, err := exec.Command("wg", "show", iface, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// addPeer adds (or updates) a client peer on the local WireGuard interface.
// persistent-keepalive=5 triggers an immediate handshake, opening the CGNAT
// mapping so the client can reach Pi's wgd0 port directly.
func addPeer(iface, pubKey, vpnIP string) {
	args := []string{
		"set", iface,
		"peer", pubKey,
		"allowed-ips", vpnIP,
		"persistent-keepalive", "5",
	}
	if out, err := exec.Command("wg", args...).CombinedOutput(); err != nil {
		log.Printf("wg set peer %s: %v — %s", short(pubKey), err, out)
	} else {
		log.Printf("peer synced: %s vpn=%s", short(pubKey), vpnIP)
	}
}

func removePeer(iface, pubKey string) {
	if out, err := exec.Command("wg", "set", iface, "peer", pubKey, "remove").CombinedOutput(); err != nil {
		log.Printf("wg remove peer %s: %v — %s", short(pubKey), err, out)
	} else {
		log.Printf("peer removed: %s", short(pubKey))
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// ── status for healthz ────────────────────────────────────────────────────────

type status struct {
	mu        sync.Mutex
	connected bool
	peerCount int
	lastSeen  time.Time
	selfIP    string
}

var st = &status{}

func (s *status) setConnected(connected bool, selfIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = connected
	if selfIP != "" {
		s.selfIP = selfIP
	}
	s.lastSeen = time.Now()
}

func (s *status) setPeers(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerCount = n
	s.lastSeen = time.Now()
}

func (s *status) json() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf(`{"ok":%v,"peers":%d,"selfIP":%q,"lastSeen":%q}`,
		s.connected, s.peerCount, s.selfIP, s.lastSeen.Format(time.RFC3339))
}

// ── agent ─────────────────────────────────────────────────────────────────────

type agent struct {
	iface      string
	coord      string
	accessCode string
	name       string
	known      map[string]bool // pubkeys of currently synced client peers
}

func (a *agent) run() {
	a.known = map[string]bool{}
	b := newBackoff()
	for {
		if err := a.connect(); err != nil {
			wait := b.next()
			log.Printf("coordinator error: %v — retry in %s", err, wait.Round(time.Millisecond))
			st.setConnected(false, "")
		} else {
			b.reset()
		}
		time.Sleep(b.next())
	}
}

func (a *agent) connect() error {
	pubKey, err := wgPubKey(a.iface)
	if err != nil {
		return fmt.Errorf("wg pubkey: %w", err)
	}
	log.Printf("local pubkey: %s", short(pubKey))

	conn, _, err := websocket.DefaultDialer.Dial(a.coord+"/ws", nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	log.Printf("connected to coordinator %s", a.coord)

	hello, _ := encode(typeHello, helloMsg{
		AccessCode: a.accessCode,
		PubKey:     pubKey,
		Role:       "exit",
		Name:       a.name,
	})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		return err
	}

	// Wait for welcome to get STUN endpoint, then gather and report candidates.
	var stunEndpoint string

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case typeWelcome:
			var w welcomeMsg
			if json.Unmarshal(env.Data, &w) == nil {
				stunEndpoint = w.STUNEndpoint
				log.Printf("registered: selfIP=%s stun=%s", w.SelfIP, stunEndpoint)
				st.setConnected(true, w.SelfIP)
			}
			// Gather and report candidates now that we know the STUN server.
			go func() {
				cands := gatherCandidates(stunEndpoint)
				if len(cands) == 0 {
					return
				}
				msg, err := encode(typeEndpoints, endpointsMsg{Candidates: cands})
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					log.Printf("send endpoints: %v", err)
				} else {
					log.Printf("reported %d candidates (stun=%s)", len(cands), stunEndpoint)
				}
			}()

		case typePeers:
			var pm peersMsg
			if err := json.Unmarshal(env.Data, &pm); err != nil {
				continue
			}
			a.syncPeers(pm.Peers)
			st.setPeers(len(pm.Peers))

		case typePing:
			pong, _ := encode(typePong, nil)
			conn.WriteMessage(websocket.TextMessage, pong)
		}
	}
}

func (a *agent) syncPeers(peers []peerInfo) {
	seen := map[string]bool{}
	for _, p := range peers {
		if p.Role != "client" {
			continue
		}
		seen[p.PubKey] = true
		if !a.known[p.PubKey] {
			addPeer(a.iface, p.PubKey, p.VPNIP)
			a.known[p.PubKey] = true
		}
	}
	for pk := range a.known {
		if !seen[pk] {
			removePeer(a.iface, pk)
			delete(a.known, pk)
		}
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	coord      := flag.String("coordinator",  "ws://65.20.80.3:8089", "coordinator WSS URL")
	iface      := flag.String("wg-iface",     "wgd0",                 "local WireGuard interface to manage")
	code       := flag.String("access-code",  "",                      "coordinator access code (empty = dev mode)")
	name       := flag.String("name",         "pi-india",              "human name for this exit node")
	healthAddr := flag.String("healthz-addr", ":8090",                 "HTTP healthz listen address")
	flag.Parse()

	log.Printf("rpn-agent starting: iface=%s coordinator=%s", *iface, *coord)

	// Healthz endpoint for monitoring / systemd checks.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(st.json()))
		})
		log.Printf("healthz on %s", *healthAddr)
		if err := http.ListenAndServe(*healthAddr, mux); err != nil {
			log.Printf("healthz: %v", err)
		}
	}()

	a := &agent{
		iface:      *iface,
		coord:      *coord,
		accessCode: *code,
		name:       *name,
	}
	a.run()
}
