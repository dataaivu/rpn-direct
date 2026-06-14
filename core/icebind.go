package core

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// iceBind adapts a single connected net.Conn (a pion *ice.Conn — direct or
// TURN-relayed, chosen transparently by ICE) into a wireguard-go conn.Bind.
//
// This is the architectural heart of the global puncher: wireguard-go does all
// the crypto and tunnelling, but every packet rides the ICE-selected path. WG's
// own notion of "endpoint" is irrelevant — there is exactly one peer and one
// connection, so Send/receive always use iceConn.
type iceBind struct {
	mu      sync.Mutex
	iceConn net.Conn
	ep      *iceEndpoint
	closed  bool
}

func newIceBind(c net.Conn) *iceBind {
	return &iceBind{iceConn: c, ep: &iceEndpoint{}}
}

// ── conn.Bind ───────────────────────────────────────────────────────────────

func (b *iceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *iceBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	c := b.iceConn
	b.mu.Unlock()
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.Read(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = b.ep
	return 1, nil
}

func (b *iceBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	c := b.iceConn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *iceBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.iceConn != nil {
		return b.iceConn.Close()
	}
	return nil
}

func (b *iceBind) SetMark(uint32) error { return nil }
func (b *iceBind) BatchSize() int       { return 1 }

func (b *iceBind) ParseEndpoint(string) (conn.Endpoint, error) { return b.ep, nil }

// ── conn.Endpoint (single static peer) ──────────────────────────────────────

type iceEndpoint struct{}

func (e *iceEndpoint) ClearSrc()           {}
func (e *iceEndpoint) SrcToString() string { return "" }
func (e *iceEndpoint) DstToString() string { return "ice" }
func (e *iceEndpoint) DstToBytes() []byte  { return []byte{0} }
func (e *iceEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *iceEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
