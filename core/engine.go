package core

// Package core is the shared ICE + userspace-WireGuard engine that gives RPN
// Direct globally-robust NAT traversal. It is consumed two ways:
//   - Android: `gomobile bind` produces an .aar; the app calls Start/Stop/Status.
//   - Pi agent: imported natively; calls RunExit with a kernel-or-userspace tun.
//
// Path selection is delegated to pion/ice: it gathers host, server-reflexive
// (STUN) and relay (TURN) candidates, runs connectivity checks, and hands back a
// single net.Conn over the best working pair — direct when punchable, TURN-relay
// when not. wireguard-go then tunnels over that conn via iceBind.
//
// STATUS: first cut of the hard part. Compiles/iterates via CI (go vet + gomobile
// + gradle). Implements a single client<->exit session. Multi-peer on the Pi
// (one ICE conn per customer, demuxing bind) is the next iteration — see README.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config is the JSON passed to Start/RunExit. Keys are WireGuard base64 keys.
type Config struct {
	WSURL      string `json:"wsURL"`      // coordinator control channel, e.g. ws://65.20.80.3:8089/ws
	AccessCode string `json:"accessCode"` // customer access code (client) or fleet token (exit)
	PrivateKey string `json:"privateKey"` // our WireGuard private key (base64)
	Role       string `json:"role"`       // RoleClient | RoleExit
	Name       string `json:"name"`

	// Exit-only:
	TunName string `json:"tunName"` // userspace tun device name, e.g. "rpn0"
	HubCIDR string `json:"hubCIDR"` // the Pi's hub address, e.g. "10.100.0.2/24"
}

type engine struct {
	mu      sync.Mutex
	cfg     Config
	sig     *signaler
	agent   *ice.Agent
	dev     *device.Device
	bind    *multiBind
	status  string
	cancel  context.CancelFunc
	running bool
}

var (
	gMu     sync.Mutex
	gEngine *engine
)

// Start brings the tunnel up over the best ICE path. configJSON is a Config;
// tunFd is the file descriptor from Android's VpnService.establish(). Returns an
// error string ("" on success) — gomobile-friendly.
func Start(configJSON string, tunFd int) string {
	gMu.Lock()
	defer gMu.Unlock()
	if gEngine != nil && gEngine.running {
		return "already running"
	}
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "bad config: " + err.Error()
	}
	e := &engine{cfg: cfg, status: "starting"}
	if err := e.start(tunFd); err != nil {
		e.stop()
		return err.Error()
	}
	gEngine = e
	return ""
}

// Stop tears the tunnel down.
func Stop() {
	gMu.Lock()
	defer gMu.Unlock()
	if gEngine != nil {
		gEngine.stop()
		gEngine = nil
	}
}

// Status returns a short human-readable state string for the UI.
func Status() string {
	gMu.Lock()
	defer gMu.Unlock()
	if gEngine == nil {
		return "down"
	}
	gEngine.mu.Lock()
	defer gEngine.mu.Unlock()
	return gEngine.status
}

func (e *engine) setStatus(s string) {
	e.mu.Lock()
	e.status = s
	e.mu.Unlock()
}

func (e *engine) start(tunFd int) error {
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	sig, err := dialSignaler(e.cfg.WSURL)
	if err != nil {
		return fmt.Errorf("signaling dial: %w", err)
	}
	e.sig = sig

	pub, err := pubFromPriv(e.cfg.PrivateKey)
	if err != nil {
		return err
	}
	welcome, err := sig.hello(Hello{
		AccessCode: e.cfg.AccessCode,
		PubKey:     pub,
		Role:       e.cfg.Role,
		Name:       e.cfg.Name,
	}, 10*time.Second)
	if err != nil {
		return err
	}
	e.setStatus("registered")

	// Build the ICE agent with STUN + TURN servers from the welcome.
	urls := stunTurnURLs(welcome)
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:           urls,
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
	})
	if err != nil {
		return fmt.Errorf("ice agent: %w", err)
	}
	e.agent = agent

	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	var gathered []Candidate
	var gmu sync.Mutex
	gatherDone := make(chan struct{})
	agent.OnCandidate(func(c ice.Candidate) {
		if c == nil { // nil => gathering complete
			close(gatherDone)
			return
		}
		gmu.Lock()
		gathered = append(gathered, Candidate{Type: c.Type().String(), Addr: c.Marshal()})
		gmu.Unlock()
	})
	if err := agent.GatherCandidates(); err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	select {
	case <-gatherDone:
	case <-time.After(5 * time.Second):
	}

	gmu.Lock()
	cands := append([]Candidate(nil), gathered...)
	gmu.Unlock()
	if err := sig.sendEndpoints(Endpoints{Candidates: cands, Ufrag: localUfrag, Pwd: localPwd}); err != nil {
		return err
	}

	// Run the rest (peer selection, punch wait, ICE connect, WG bring-up) async.
	go e.session(ctx, tunFd, pub)
	e.running = true
	return nil
}

// session waits for the peer's candidates (via Punch), runs ICE, then starts WG.
func (e *engine) session(ctx context.Context, tunFd int, selfPub string) {
	controlling := e.cfg.Role == RoleClient

	// Client initiates: find the exit peer and ask the coordinator to introduce us.
	if controlling {
		exit := e.awaitExitPeer(ctx)
		if exit == "" {
			e.setStatus("no exit available")
			return
		}
		e.sig.connect(exit)
	}

	var punch Punch
	select {
	case punch = <-e.sig.punchCh:
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
		e.setStatus("punch timeout")
		return
	}

	for _, c := range punch.Candidates {
		cand, err := ice.UnmarshalCandidate(c.Addr)
		if err == nil {
			e.agent.AddRemoteCandidate(cand)
		}
	}

	e.setStatus("connecting")
	var iceConn *ice.Conn
	var err error
	if controlling {
		iceConn, err = e.agent.Dial(ctx, punch.Ufrag, punch.Pwd)
	} else {
		iceConn, err = e.agent.Accept(ctx, punch.Ufrag, punch.Pwd)
	}
	if err != nil {
		e.setStatus("ice failed: " + err.Error())
		return
	}

	// Report which path won (direct vs relay) so the coordinator can log it.
	via := "direct"
	if pair, perr := e.agent.GetSelectedCandidatePair(); perr == nil && pair != nil {
		if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
			via = "relay"
		}
	}
	e.sig.result(Result{PeerPubKey: punch.PeerPubKey, OK: true, Via: via})
	e.setStatus("up (" + via + ")")

	if err := e.bringUpWireguard(tunFd, selfPub, punch.PeerPubKey, iceConn); err != nil {
		e.setStatus("wg failed: " + err.Error())
	}
}

// awaitExitPeer polls the peer list until an exit appears. Candidates flow via
// the offer/answer exchange, so we select by role alone.
func (e *engine) awaitExitPeer(ctx context.Context) string {
	deadline := time.After(15 * time.Second)
	for {
		select {
		case peers := <-e.sig.peersCh:
			for _, p := range peers {
				if p.Role == RoleExit {
					return p.PubKey
				}
			}
		case <-deadline:
			return ""
		case <-ctx.Done():
			return ""
		}
	}
}

func (e *engine) bringUpWireguard(tunFd int, selfPub, peerWGPub string, iceConn *ice.Conn) error {
	tdev, _, err := tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		return fmt.Errorf("tun from fd: %w", err)
	}
	bind := newMultiBind()
	bind.AddPeer(peerWGPub, iceConn)
	e.bind = bind
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelError, "rpn: "))
	e.dev = dev

	privHex, err := keyB64ToHex(e.cfg.PrivateKey)
	if err != nil {
		return err
	}
	peerHex, err := keyB64ToHex(peerWGPub)
	if err != nil {
		return err
	}
	// endpoint=<peer pubkey> tells the bind which ICE conn to use for this peer.
	uapi := strings.Join([]string{
		"private_key=" + privHex,
		"public_key=" + peerHex,
		"endpoint=" + peerWGPub,
		"persistent_keepalive_interval=15",
		"allowed_ip=0.0.0.0/0",
		"",
	}, "\n")
	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}
	return nil
}

func (e *engine) stop() {
	if e.cancel != nil {
		e.cancel()
	}
	if e.dev != nil {
		e.dev.Close()
	}
	if e.agent != nil {
		e.agent.Close()
	}
	if e.sig != nil {
		e.sig.close()
	}
	e.running = false
	e.setStatus("down")
}

// ── helpers ─────────────────────────────────────────────────────────────────

func stunTurnURLs(w *Welcome) []*stun.URI {
	var urls []*stun.URI
	if u := parseHostPort(w.STUNEndpoint, stun.SchemeTypeSTUN); u != nil {
		urls = append(urls, u)
	}
	if u := parseHostPort(w.STUN2Endpoint, stun.SchemeTypeSTUN); u != nil {
		urls = append(urls, u)
	}
	if u := parseHostPort(w.RelayEndpoint, stun.SchemeTypeTURN); u != nil {
		u.Proto = stun.ProtoTypeUDP
		urls = append(urls, u)
	}
	return urls
}

func parseHostPort(s string, scheme stun.SchemeType) *stun.URI {
	if s == "" {
		return nil
	}
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	return &stun.URI{Scheme: scheme, Host: host, Port: port}
}

// keyB64ToHex converts a base64 WireGuard key (44 chars) to the 64-char hex
// the wireguard-go UAPI expects.
func keyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key not 32 bytes (got %d)", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// PublicKey derives the base64 WireGuard public key from a base64 private key.
// Exposed for the mobile wrapper so Android needs no WireGuard crypto library.
// Returns "" on error.
func PublicKey(privB64 string) string {
	pub, err := pubFromPriv(privB64)
	if err != nil {
		return ""
	}
	return pub
}

// pubFromPriv derives a Curve25519 public key (base64) from a base64 private key.
func pubFromPriv(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("bad private key")
	}
	pub, err := curve25519Pub(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
