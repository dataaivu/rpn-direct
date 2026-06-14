package core

import (
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

// wgLogLevel lets RPN_WG_LOG=verbose|error|silent control wireguard-go logging
// without a rebuild. Defaults to error.
func wgLogLevel() int {
	switch os.Getenv("RPN_WG_LOG") {
	case "verbose":
		return device.LogLevelVerbose
	case "silent":
		return device.LogLevelSilent
	default:
		return device.LogLevelError
	}
}

// short truncates a key/id for log lines.
func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// curve25519Pub derives the WireGuard public key from a (already clamped) private
// key. wg genkey emits clamped keys, so a plain X25519 against the basepoint is
// correct.
func curve25519Pub(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
