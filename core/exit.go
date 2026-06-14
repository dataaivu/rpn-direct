package core

// Pi exit engine. One userspace-WireGuard device + multiBind serves every
// customer. For each client the coordinator introduces (via an Offer), the exit
// mints a dedicated ICE agent with its own short-term credentials, answers, runs
// connectivity checks, and on success registers the resulting ice.Conn as a new
// WireGuard peer. Native-only (the Pi is an ARM Linux binary); not gomobile.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type exitEngine struct {
	cfg     Config
	sig     *signaler
	dev     *device.Device
	bind    *multiBind
	privHex string

	mu       sync.Mutex
	sessions map[string]*ice.Agent // clientPubKey -> agent
}

// RunExit brings up the exit and serves customers until ctx-style failure. It
// blocks. Returns an error string ("" never, in practice — it loops).
func RunExit(configJSON string) string {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "bad config: " + err.Error()
	}
	if cfg.Role == "" {
		cfg.Role = RoleExit
	}
	e := &exitEngine{cfg: cfg, sessions: map[string]*ice.Agent{}}
	if err := e.run(); err != nil {
		return err.Error()
	}
	return ""
}

func (e *exitEngine) run() error {
	privHex, err := keyB64ToHex(e.cfg.PrivateKey)
	if err != nil {
		return err
	}
	e.privHex = privHex

	// Userspace tun + WireGuard device shared by all customers.
	tdev, err := tun.CreateTUN(e.cfg.TunName, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("create tun %s: %w", e.cfg.TunName, err)
	}
	if err := e.configureTun(); err != nil {
		return fmt.Errorf("configure tun: %w", err)
	}
	e.bind = newMultiBind()
	e.dev = device.NewDevice(tdev, e.bind, device.NewLogger(wgLogLevel(), "rpn-exit: "))
	if err := e.dev.IpcSet("private_key=" + privHex + "\n"); err != nil {
		return fmt.Errorf("set private key: %w", err)
	}
	if err := e.dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}

	pub, err := pubFromPriv(e.cfg.PrivateKey)
	if err != nil {
		return err
	}

	// Reconnect loop for the signaling channel.
	for {
		if err := e.serve(pub); err != nil {
			log.Printf("exit serve: %v — reconnecting in 3s", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func (e *exitEngine) serve(pub string) error {
	sig, err := dialSignaler(e.cfg.WSURL)
	if err != nil {
		return err
	}
	e.sig = sig
	if _, err := sig.hello(Hello{AccessCode: e.cfg.AccessCode, PubKey: pub, Role: RoleExit, Name: e.cfg.Name}, 10*time.Second); err != nil {
		return err
	}
	log.Printf("exit registered with coordinator as %s", short(pub))

	for {
		select {
		case offer := <-sig.offerCh:
			go e.handleOffer(offer)
		case <-time.After(90 * time.Second):
			// liveness probe: if the socket died, a write will fail
			if err := sig.send(TypePong, nil); err != nil {
				return err
			}
		}
	}
}

// handleOffer runs one customer's ICE session and adds them as a WireGuard peer.
func (e *exitEngine) handleOffer(o Offer) {
	urls := stunTurnURLs(e.sigWelcome())
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:            urls,
		NetworkTypes:    []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:  []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
		InterfaceFilter: iceInterfaceFilter,
	})
	if err != nil {
		log.Printf("offer %s: agent: %v", short(o.ClientPubKey), err)
		return
	}
	agent.OnConnectionStateChange(func(s ice.ConnectionState) {
		log.Printf("exit ICE state (%s): %s", short(o.ClientPubKey), s)
	})
	e.mu.Lock()
	if old := e.sessions[o.ClientPubKey]; old != nil {
		old.Close()
	}
	e.sessions[o.ClientPubKey] = agent
	e.mu.Unlock()

	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return
	}

	var gathered []Candidate
	var gmu sync.Mutex
	done := make(chan struct{})
	agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(done)
			return
		}
		gmu.Lock()
		gathered = append(gathered, Candidate{Type: c.Type().String(), Addr: c.Marshal()})
		gmu.Unlock()
	})
	if err := agent.GatherCandidates(); err != nil {
		return
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

	// Add the client's candidates and answer with ours.
	for _, c := range o.Candidates {
		if cand, err := ice.UnmarshalCandidate(c.Addr); err == nil {
			agent.AddRemoteCandidate(cand)
		}
	}
	gmu.Lock()
	cands := append([]Candidate(nil), gathered...)
	gmu.Unlock()
	e.sig.answer(Answer{
		SessionID:    o.SessionID,
		ClientPubKey: o.ClientPubKey,
		Ufrag:        localUfrag,
		Pwd:          localPwd,
		Candidates:   cands,
	})

	// The exit is the controlled side: Accept. Bound the establishment with a
	// timeout, but cancel only the timer — the returned conn lives independently.
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, err := agent.Accept(acceptCtx, o.Ufrag, o.Pwd)
	acceptCancel()
	if err != nil {
		log.Printf("offer %s: accept: %v", short(o.ClientPubKey), err)
		return
	}

	// Register the customer as a WireGuard peer over this ICE conn.
	e.bind.AddPeer(o.ClientPubKey, conn)
	peerHex, err := keyB64ToHex(o.ClientPubKey)
	if err != nil {
		return
	}
	allowed := o.ClientVPNIP
	if !strings.Contains(allowed, "/") {
		allowed += "/32"
	}
	uapi := strings.Join([]string{
		"public_key=" + peerHex,
		"endpoint=" + o.ClientPubKey,
		"persistent_keepalive_interval=15",
		"allowed_ip=" + allowed,
		"",
	}, "\n")
	if err := e.dev.IpcSet(uapi); err != nil {
		log.Printf("offer %s: ipc set peer: %v", short(o.ClientPubKey), err)
		return
	}
	log.Printf("customer up: %s vpn=%s", short(o.ClientPubKey), allowed)
}

func (e *exitEngine) sigWelcome() *Welcome {
	e.sig.mu.Lock()
	defer e.sig.mu.Unlock()
	return e.sig.welcome
}

// configureTun assigns the hub address and brings the link up (Linux).
func (e *exitEngine) configureTun() error {
	if e.cfg.HubCIDR == "" {
		return nil
	}
	if out, err := exec.Command("ip", "addr", "add", e.cfg.HubCIDR, "dev", e.cfg.TunName).CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "File exists") {
		return fmt.Errorf("ip addr add: %v — %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", e.cfg.TunName, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link up: %v — %s", err, out)
	}
	return nil
}
