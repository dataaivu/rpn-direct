package core

import "golang.org/x/crypto/curve25519"

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
