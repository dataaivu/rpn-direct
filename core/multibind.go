package core

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// multiBind is a wireguard-go conn.Bind that fans ONE WireGuard device out over
// MANY ICE connections — one per customer. This is what lets a single Pi exit
// serve every customer from one userspace-WireGuard device:
//   - Send(ep): routes the packet to that peer's *ice.Conn (looked up by id).
//   - receive:  merges reads from all peers' conns, tagging each packet with the
//               peer's endpoint so WireGuard's crypto-routing attributes it right.
//
// The client side is just the degenerate case: one peer.
type multiBind struct {
	mu      sync.RWMutex
	peers   map[string]*boundPeer // id (WG pubkey) -> peer
	recvCh  chan recvItem
	closeCh chan struct{}
	closed  bool
}

type boundPeer struct {
	id   string
	conn net.Conn
	ep   *peerEndpoint
	stop chan struct{}
}

type recvItem struct {
	data []byte
	ep   *peerEndpoint
}

func newMultiBind() *multiBind {
	return &multiBind{
		peers:   map[string]*boundPeer{},
		recvCh:  make(chan recvItem, 256),
		closeCh: make(chan struct{}),
	}
}

// AddPeer registers a customer's ICE conn and starts reading from it. id is the
// peer's WireGuard public key (base64). Call IpcSet with endpoint=<id> so WG
// routes sends for this peer through here.
func (b *multiBind) AddPeer(id string, c net.Conn) {
	ep := &peerEndpoint{id: id}
	bp := &boundPeer{id: id, conn: c, ep: ep, stop: make(chan struct{})}
	b.mu.Lock()
	if old, ok := b.peers[id]; ok {
		close(old.stop)
		old.conn.Close()
	}
	b.peers[id] = bp
	b.mu.Unlock()
	go b.readPeer(bp)
}

func (b *multiBind) RemovePeer(id string) {
	b.mu.Lock()
	if bp, ok := b.peers[id]; ok {
		close(bp.stop)
		bp.conn.Close()
		delete(b.peers, id)
	}
	b.mu.Unlock()
}

func (b *multiBind) readPeer(bp *boundPeer) {
	buf := make([]byte, 1500)
	for {
		n, err := bp.conn.Read(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case b.recvCh <- recvItem{data: pkt, ep: bp.ep}:
		case <-bp.stop:
			return
		case <-b.closeCh:
			return
		}
	}
}

// ── conn.Bind ───────────────────────────────────────────────────────────────

func (b *multiBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *multiBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case it := <-b.recvCh:
		sizes[0] = copy(packets[0], it.data)
		eps[0] = it.ep
		return 1, nil
	case <-b.closeCh:
		return 0, net.ErrClosed
	}
}

func (b *multiBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	pe, ok := ep.(*peerEndpoint)
	if !ok {
		return nil
	}
	b.mu.RLock()
	bp := b.peers[pe.id]
	b.mu.RUnlock()
	if bp == nil {
		return nil // peer gone; drop silently
	}
	for _, buf := range bufs {
		if _, err := bp.conn.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *multiBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	close(b.closeCh)
	for _, bp := range b.peers {
		bp.conn.Close()
	}
	b.peers = map[string]*boundPeer{}
	return nil
}

func (b *multiBind) SetMark(uint32) error { return nil }
func (b *multiBind) BatchSize() int       { return 1 }

// ParseEndpoint maps a UAPI endpoint=<id> line to the peer's endpoint. WG calls
// this when a peer is configured, so set endpoint=<peer pubkey> in IpcSet.
func (b *multiBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	b.mu.RLock()
	bp := b.peers[s]
	b.mu.RUnlock()
	if bp != nil {
		return bp.ep, nil
	}
	return &peerEndpoint{id: s}, nil
}

// ── conn.Endpoint (identifies one peer) ─────────────────────────────────────

type peerEndpoint struct{ id string }

func (e *peerEndpoint) ClearSrc()           {}
func (e *peerEndpoint) SrcToString() string { return "" }
func (e *peerEndpoint) DstToString() string { return "ice:" + e.id }
func (e *peerEndpoint) DstToBytes() []byte  { return []byte(e.id) }
func (e *peerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *peerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
