// Command rpn-exit runs the ICE exit engine on a Pi. It stands up a userspace
// WireGuard device (new tun, distinct from any kernel wg) and serves every
// customer over a hole-punched (or TURN-relayed) ICE path. Coexists with the
// existing kernel-wg / Tailscale setup — different interface, subnet, keys.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/dataaivu/rpn-direct/core"
)

func main() {
	ws := flag.String("ws", "ws://65.20.80.3:8089/ws", "coordinator WS URL")
	fleet := flag.String("fleet-token", os.Getenv("RPN_FLEET_TOKEN"), "fleet token (or RPN_FLEET_TOKEN)")
	priv := flag.String("private-key", os.Getenv("RPN_EXIT_PRIVKEY"), "WG private key base64 (or RPN_EXIT_PRIVKEY)")
	tunName := flag.String("tun", "rpn0", "userspace tun device name")
	hub := flag.String("hub-cidr", "10.100.0.2/24", "this exit's hub address")
	flag.Parse()

	if *priv == "" {
		log.Fatal("private key required (-private-key or RPN_EXIT_PRIVKEY)")
	}

	cfg := core.Config{
		WSURL:      *ws,
		AccessCode: *fleet,
		PrivateKey: *priv,
		Role:       core.RoleExit,
		TunName:    *tunName,
		HubCIDR:    *hub,
		Name:       "pi-exit",
	}
	b, _ := json.Marshal(cfg)
	log.Printf("rpn-exit: ws=%s tun=%s hub=%s", *ws, *tunName, *hub)
	if e := core.RunExit(string(b)); e != "" {
		log.Fatalf("exit failed: %s", e)
	}
}
