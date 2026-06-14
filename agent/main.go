package main

// RPN Direct — Pi exit-node agent (fleet edition).
//
// Runs on every shipped Pi. On first boot the Pi is already registered (setup.sh
// did that). This agent:
//   1. Discovers its own STUN (public) endpoint.
//   2. POSTs a heartbeat every 30s → coordinator tracks liveness + gets customer list.
//   3. Syncs the live customer list into the local WireGuard interface.
//   4. Customers connect DIRECTLY to this Pi — VPS carries zero data.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	pionstun "github.com/pion/stun/v2"
)

// ── backoff ───────────────────────────────────────────────────────────────────

type backoff struct {
	attempt int
	base    time.Duration
	max     time.Duration
}

func newBackoff() *backoff { return &backoff{base: 2 * time.Second, max: 60 * time.Second} }

func (b *backoff) next() time.Duration {
	d := b.base
	for i := 0; i < b.attempt; i++ {
		d *= 2
		if d > b.max {
			d = b.max
			break
		}
	}
	b.attempt++
	return d + time.Duration(rand.Int63n(int64(d)/5))
}

func (b *backoff) reset() { b.attempt = 0 }

// ── STUN discovery ────────────────────────────────────────────────────────────

func stunSRFLX(serverAddr string) string {
	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, err := pionstun.Build(pionstun.TransactionID, pionstun.BindingRequest)
	if err != nil {
		return ""
	}
	if _, err := conn.Write(req.Raw); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	resp := &pionstun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return ""
	}
	var xor pionstun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", xor.IP.String(), xor.Port)
}

// ── wg helpers ────────────────────────────────────────────────────────────────

func wgPubKey(iface string) string {
	out, err := exec.Command("wg", "show", iface, "public-key").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func wgPeerCount(iface string) int {
	out, err := exec.Command("wg", "show", iface, "peers").Output()
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(out)))
}

func addPeer(iface, pubKey, vpnIP string) {
	args := []string{"set", iface, "peer", pubKey, "allowed-ips", vpnIP, "persistent-keepalive", "5"}
	if out, err := exec.Command("wg", args...).CombinedOutput(); err != nil {
		log.Printf("wg add peer %s: %v — %s", short(pubKey), err, out)
	} else {
		log.Printf("peer added: %s vpn=%s", short(pubKey), vpnIP)
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

// ── Pi identity ───────────────────────────────────────────────────────────────

// piSerial reads the Pi's CPU serial from /proc/cpuinfo (stable hardware ID).
// Falls back to the MAC address of the first non-loopback interface.
func piSerial() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Serial") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					s := strings.TrimSpace(parts[1])
					if s != "" && s != "0000000000000000" {
						return s
					}
				}
			}
		}
	}
	// Fallback: first non-loopback MAC
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr == nil {
			continue
		}
		return strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
	}
	return "unknown"
}

// ── coordinator REST client ───────────────────────────────────────────────────

type coordClient struct {
	base       string
	httpClient *http.Client
}

func newCoordClient(base string) *coordClient {
	return &coordClient{
		base:       strings.TrimRight(base, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type heartbeatReq struct {
	PiID      string `json:"pi_id"`
	PubKey    string `json:"pubkey"`
	StunEP    string `json:"stun_ep"`
	Customers int    `json:"customers"`
}

type customerEntry struct {
	PubKey string `json:"pubkey"`
	VPNIP  string `json:"vpn_ip"`
}

func (c *coordClient) heartbeat(req heartbeatReq) ([]customerEntry, error) {
	body, _ := json.Marshal(req)
	resp, err := c.httpClient.Post(c.base+"/pi/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("heartbeat %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Customers []customerEntry `json:"customers"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.Customers, nil
}

// ── status ────────────────────────────────────────────────────────────────────

type agentStatus struct {
	mu        sync.Mutex
	stunEP    string
	customers int
	lastBeat  time.Time
	ok        bool
}

var status = &agentStatus{}

// ── agent ─────────────────────────────────────────────────────────────────────

type agent struct {
	piID       string
	iface      string
	coord      *coordClient
	stunServer string
	known      map[string]bool
}

func (a *agent) run() {
	a.known = map[string]bool{}
	b := newBackoff()

	for {
		err := a.tick()
		if err != nil {
			log.Printf("tick error: %v", err)
			wait := b.next()
			time.Sleep(wait)
		} else {
			b.reset()
			time.Sleep(30 * time.Second)
		}
	}
}

func (a *agent) tick() error {
	// Refresh STUN endpoint (it changes when CGNAT remaps)
	stunEP := stunSRFLX(a.stunServer)
	if stunEP != "" {
		status.mu.Lock()
		status.stunEP = stunEP
		status.mu.Unlock()
	}

	pubKey := wgPubKey(a.iface)
	customers := wgPeerCount(a.iface)

	resp, err := a.coord.heartbeat(heartbeatReq{
		PiID:      a.piID,
		PubKey:    pubKey,
		StunEP:    stunEP,
		Customers: customers,
	})
	if err != nil {
		return err
	}

	a.syncPeers(resp)

	status.mu.Lock()
	status.customers = len(resp)
	status.lastBeat = time.Now()
	status.ok = true
	status.mu.Unlock()

	return nil
}

func (a *agent) syncPeers(list []customerEntry) {
	seen := map[string]bool{}
	for _, c := range list {
		if c.PubKey == "" {
			continue
		}
		seen[c.PubKey] = true
		if !a.known[c.PubKey] {
			addPeer(a.iface, c.PubKey, c.VPNIP)
			a.known[c.PubKey] = true
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
	coord       := flag.String("coordinator",   "http://65.20.80.3:8089", "coordinator base URL")
	iface       := flag.String("wg-iface",      "wgd0",                   "WireGuard interface to manage")
	stunServer  := flag.String("stun",          "65.20.80.3:3479",        "STUN server for endpoint discovery")
	healthAddr  := flag.String("healthz-addr",  ":8090",                  "healthz HTTP listen address")
	piIDFlag    := flag.String("pi-id",         "",                       "Pi serial (auto-detected if empty)")
	flag.Parse()

	piID := *piIDFlag
	if piID == "" {
		piID = piSerial()
	}
	if piID == "" || piID == "unknown" {
		log.Fatalf("could not determine Pi serial — pass -pi-id manually")
	}
	log.Printf("rpn-agent: pi_id=%s iface=%s coordinator=%s", piID, *iface, *coord)

	a := &agent{
		piID:       piID,
		iface:      *iface,
		coord:      newCoordClient(*coord),
		stunServer: *stunServer,
	}

	// Healthz
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			status.mu.Lock()
			s := fmt.Sprintf(`{"ok":%v,"stun_ep":%q,"customers":%d,"last_beat":%q}`,
				status.ok, status.stunEP, status.customers, status.lastBeat.Format(time.RFC3339))
			status.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(s))
		})
		log.Printf("healthz on %s", *healthAddr)
		http.ListenAndServe(*healthAddr, mux)
	}()

	a.run()
}
