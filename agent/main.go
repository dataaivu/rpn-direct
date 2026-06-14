package main

// RPN Direct — Pi exit-node agent.
//
// Runs on the Raspberry Pi (ARMv7). Connects to the coordinator as role=exit,
// receives the live client peer list, and syncs it into the local kernel
// WireGuard interface (wgd0) via the `wg` CLI tool.
//
// When a new client peer is added with persistent-keepalive=5, kernel WireGuard
// immediately initiates a handshake → keepalive packet → opens the CGNAT
// mapping for that client's IP. The coordinator's /exit/info endpoint then
// serves Pi's current CGNAT endpoint (read from wgd0 by the VPS coordinator),
// and the Android client can connect WireGuard directly to Pi.

import (
	"encoding/json"
	"flag"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// ── minimal wire types (mirrors coordinator/protocol.go) ─────────────────────

const (
	typeHello   = "hello"
	typeWelcome = "welcome"
	typePeers   = "peers"
	typePing    = "ping"
	typePong    = "pong"
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

type peerInfo struct {
	PubKey string `json:"pubKey"`
	Role   string `json:"role"`
	VPNIP  string `json:"vpnIP"` // e.g. "10.99.0.101/32"
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

// ── wg helpers ────────────────────────────────────────────────────────────────

func wgPubKey(iface string) (string, error) {
	out, err := exec.Command("wg", "show", iface, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// addPeer adds (or updates) a client peer on the local WireGuard interface.
// The persistent-keepalive triggers an immediate handshake, opening the CGNAT
// mapping so the client can reach Pi's wgd0 port directly.
func addPeer(iface, pubKey, vpnIP string) {
	// vpnIP arrives as "10.99.0.101/32" — use as-is for allowed-ips
	args := []string{
		"set", iface,
		"peer", pubKey,
		"allowed-ips", vpnIP,
		"persistent-keepalive", "5",
	}
	if out, err := exec.Command("wg", args...).CombinedOutput(); err != nil {
		log.Printf("wg set peer %s: %v — %s", pubKey[:8], err, out)
	} else {
		log.Printf("peer synced: %s vpn=%s", pubKey[:8], vpnIP)
	}
}

func removePeer(iface, pubKey string) {
	if out, err := exec.Command("wg", "set", iface, "peer", pubKey, "remove").CombinedOutput(); err != nil {
		log.Printf("wg remove peer %s: %v — %s", pubKey[:8], err, out)
	} else {
		log.Printf("peer removed: %s", pubKey[:8])
	}
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
	for {
		if err := a.connect(); err != nil {
			log.Printf("coordinator error: %v — retry in 10s", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func (a *agent) connect() error {
	pubKey, err := wgPubKey(a.iface)
	if err != nil {
		return err
	}
	log.Printf("local pubkey: %s", pubKey[:8])

	conn, _, err := websocket.DefaultDialer.Dial(a.coord+"/ws", nil)
	if err != nil {
		return err
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
		case typePeers:
			var pm peersMsg
			if err := json.Unmarshal(env.Data, &pm); err != nil {
				continue
			}
			a.syncPeers(pm.Peers)
		case typePing:
			pong, _ := encode(typePong, nil)
			conn.WriteMessage(websocket.TextMessage, pong)
		case typeWelcome:
			log.Printf("registered with coordinator")
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
	// remove peers that disappeared
	for pk := range a.known {
		if !seen[pk] {
			removePeer(a.iface, pk)
			delete(a.known, pk)
		}
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	coord := flag.String("coordinator", "ws://65.20.80.3:8089", "coordinator WSS URL")
	iface := flag.String("wg-iface", "wgd0", "local WireGuard interface to manage")
	code  := flag.String("access-code", "", "coordinator access code (empty = dev mode)")
	name  := flag.String("name", "pi-india", "human name for this exit node")
	flag.Parse()

	log.Printf("rpn-agent starting: iface=%s coordinator=%s", *iface, *coord)
	a := &agent{
		iface:      *iface,
		coord:      *coord,
		accessCode: *code,
		name:       *name,
	}
	a.run()
}
