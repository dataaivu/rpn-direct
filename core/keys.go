package core

import "golang.org/x/crypto/curve25519"

// curve25519Pub derives the WireGuard public key from a (already clamped) private
// key. wg genkey emits clamped keys, so a plain X25519 against the basepoint is
// correct.
func curve25519Pub(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
