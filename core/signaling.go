package core

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// signaler is the WSS control-channel client. It talks the coordinator's JSON
// protocol and surfaces the events the engine needs to run an ICE session.
type signaler struct {
	conn *websocket.Conn

	mu       sync.Mutex
	welcome  *Welcome
	peers    []PeerInfo
	punchCh  chan Punch
	relayCh  chan Relay
	peersCh  chan []PeerInfo
	offerCh  chan Offer
	closed   bool
	writeMu  sync.Mutex
}

func dialSignaler(wsURL string) (*signaler, error) {
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}
	s := &signaler{
		conn:    c,
		punchCh: make(chan Punch, 4),
		relayCh: make(chan Relay, 4),
		peersCh: make(chan []PeerInfo, 4),
		offerCh: make(chan Offer, 16),
	}
	go s.readLoop()
	return s, nil
}

func (s *signaler) send(t string, payload any) error {
	msg, err := encode(t, payload)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteMessage(websocket.TextMessage, msg)
}

// hello registers this peer and blocks until the Welcome arrives (or timeout).
func (s *signaler) hello(h Hello, timeout time.Duration) (*Welcome, error) {
	if err := s.send(TypeHello, h); err != nil {
		return nil, err
	}
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		w := s.welcome
		s.mu.Unlock()
		if w != nil {
			return w, nil
		}
		select {
		case <-deadline:
			return nil, errors.New("timed out waiting for welcome")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *signaler) sendEndpoints(e Endpoints) error { return s.send(TypeEndpoints, e) }
func (s *signaler) connect(peerPubKey string) error {
	return s.send(TypeConnect, Connect{PeerPubKey: peerPubKey})
}
func (s *signaler) result(r Result) error  { return s.send(TypeResult, r) }
func (s *signaler) answer(a Answer) error  { return s.send(TypeAnswer, a) }

func (s *signaler) readLoop() {
	defer func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.conn.Close()
	}()
	for {
		_, raw, err := s.conn.ReadMessage()
		if err != nil {
			return
		}
		var env Envelope
		if json.Unmarshal(raw, &env) != nil {
			continue
		}
		switch env.Type {
		case TypeWelcome:
			var w Welcome
			if json.Unmarshal(env.Data, &w) == nil {
				s.mu.Lock()
				s.welcome = &w
				s.mu.Unlock()
			}
		case TypePeers:
			var p Peers
			if json.Unmarshal(env.Data, &p) == nil {
				s.mu.Lock()
				s.peers = p.Peers
				s.mu.Unlock()
				select {
				case s.peersCh <- p.Peers:
				default:
				}
			}
		case TypePunch:
			var p Punch
			if json.Unmarshal(env.Data, &p) == nil {
				select {
				case s.punchCh <- p:
				default:
				}
			}
		case TypeRelay:
			var r Relay
			if json.Unmarshal(env.Data, &r) == nil {
				select {
				case s.relayCh <- r:
				default:
				}
			}
		case TypeOffer:
			var o Offer
			if json.Unmarshal(env.Data, &o) == nil {
				select {
				case s.offerCh <- o:
				default:
				}
			}
		case TypePing:
			s.send(TypePong, nil)
		}
	}
}

func (s *signaler) close() { s.conn.Close() }
