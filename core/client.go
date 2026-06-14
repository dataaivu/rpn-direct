package core

// Headless native client — for validating the direct path without a phone. Same
// engine as Android, but creates a real Linux tun instead of taking a VpnService
// fd. Brings the client up against the assigned exit and logs the chosen path.

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// RunClient runs the client engine with a native tun. addrCIDR is this client's
// VPN address (e.g. "10.100.10.5/32"), obtained by REST-registering first. Blocks.
func RunClient(configJSON, tunName, addrCIDR string) string {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "bad config: " + err.Error()
	}
	cfg.Role = RoleClient

	tdev, err := tun.CreateTUN(tunName, device.DefaultMTU)
	if err != nil {
		return fmt.Sprintf("create tun: %v", err)
	}
	_ = exec.Command("ip", "addr", "add", addrCIDR, "dev", tunName).Run()
	if out, err := exec.Command("ip", "link", "set", tunName, "up").CombinedOutput(); err != nil {
		return fmt.Sprintf("ip link up: %v — %s", err, out)
	}

	e := &engine{cfg: cfg, nativeTun: tdev, status: "starting"}
	if err := e.start(-1); err != nil {
		return err.Error()
	}

	// Block, logging status transitions so a test harness can see "up (direct)".
	last := ""
	for {
		time.Sleep(2 * time.Second)
		s := e.statusString()
		if s != last {
			log.Printf("status: %s", s)
			last = s
		}
	}
}

func (e *engine) statusString() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}
