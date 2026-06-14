// Command rpn-client is a headless native client for validating the direct path.
package main

import (
	"encoding/json"
	"flag"
	"log"

	"github.com/dataaivu/rpn-direct/core"
)

func main() {
	ws := flag.String("ws", "ws://65.20.80.3:8089/ws", "coordinator WS URL")
	code := flag.String("access-code", "", "customer access code")
	priv := flag.String("private-key", "", "WG private key base64")
	tunName := flag.String("tun", "rpncli0", "tun device name")
	addr := flag.String("addr", "", "this client's VPN /32, e.g. 10.100.10.5/32")
	flag.Parse()

	cfg := core.Config{WSURL: *ws, AccessCode: *code, PrivateKey: *priv, Role: core.RoleClient, Name: "test-client"}
	b, _ := json.Marshal(cfg)
	log.Printf("rpn-client: ws=%s addr=%s tun=%s", *ws, *addr, *tunName)
	if e := core.RunClient(string(b), *tunName, *addr); e != "" {
		log.Fatalf("client failed: %s", e)
	}
}
