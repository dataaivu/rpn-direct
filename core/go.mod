module github.com/dataaivu/rpn-direct/core

// Shared ICE + userspace-WireGuard engine. Imported two ways:
//   - Android app: built into an .aar via `gomobile bind` (see README.md)
//   - Pi agent:    imported directly as a native ARM binary
// Both ends MUST run this same engine so their ICE agents interoperate.

go 1.22

require (
	github.com/gorilla/websocket v1.5.1
	github.com/pion/ice/v3 v3.0.16
	github.com/pion/stun/v2 v2.0.0
	golang.org/x/crypto v0.21.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)
