package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sessionTTL              = time.Minute
	reaperInterval          = time.Second
	defaultRealmNamePattern = `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`
)

const (
	eventsBufferSize   = 16
	maxPendingAttempts = eventsBufferSize
	// maxConnectBurst caps how many connect requests one IP can make
	// back to back before the per-minute rate applies.
	maxConnectBurst = 20
)

// punchEventMaxAge is how long a queued punch event is worth delivering.
// After the connect wait times out the client still punches toward the
// cached addresses for a while, so a late event can still help. Older events
// are dropped instead of making the realm server punch at a client that has
// given up.
var punchEventMaxAge = 20 * time.Second

var (
	errSessionClosed = errors.New("session closed")
	errPendingFull   = errors.New("too many in-flight connect attempts")
	errNonceInUse    = errors.New("nonce already in use")
)

type session struct {
	id        string
	realmID   string
	addresses []string
	expires   time.Time
	events    chan sessionEvent
	// ack holds at most one pending heartbeat_ack, so acks never take
	// buffer space away from punch events.
	ack      chan struct{}
	done     chan struct{}
	closed   bool
	clientIP string
	pending  map[string]chan punchResponsePayload

	// stream identifies the /events stream that owns the session, and
	// streamCancel stops it. Only the newest stream receives events.
	stream       uint64
	streamCancel context.CancelFunc
}

type sessionEvent struct {
	kind   string
	data   any
	queued time.Time
}

type punchResponsePayload struct {
	addresses []string
}

type serverConfig struct {
	maxRealms        int
	maxRealmsPerIP   int
	connectRatePerIP int // connect requests per minute per IP, 0 = unlimited
	proxyHeader      string
	trustedProxies   []netip.Prefix
	realmIDPattern   *regexp.Regexp
}

type server struct {
	mu             sync.Mutex
	realms         map[string]*session // realmID -> session
	sessions       map[string]*session // sessionID -> session
	ipCounts       map[string]int      // clientIP -> realm count
	streamSeq      uint64
	maxRealms      int
	maxRealmsPerIP int
	proxyHeader    string
	trustedProxies []netip.Prefix
	realmIDPattern *regexp.Regexp
	connectLimiter *ipRateLimiter

	metrics            *metrics
	activeEventStreams atomic.Int64
	pendingConnects    atomic.Int64
}

func newServer(cfg serverConfig) *server {
	pat := cfg.realmIDPattern
	if pat == nil {
		pat = regexp.MustCompile(defaultRealmNamePattern)
	}
	return &server{
		realms:         make(map[string]*session),
		sessions:       make(map[string]*session),
		ipCounts:       make(map[string]int),
		maxRealms:      cfg.maxRealms,
		maxRealmsPerIP: cfg.maxRealmsPerIP,
		proxyHeader:    cfg.proxyHeader,
		trustedProxies: cfg.trustedProxies,
		realmIDPattern: pat,
		connectLimiter: newIPRateLimiter(cfg.connectRatePerIP, min(cfg.connectRatePerIP, maxConnectBurst)),
	}
}

func randToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *server) getSessionByToken(token string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[token]
	if sess == nil || sess.closed || time.Now().After(sess.expires) {
		return nil
	}
	return sess
}

func (s *server) removeSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeSessionLocked(sess)
}

func (s *server) removeSessionLocked(sess *session) {
	if sess.closed {
		return
	}
	sess.closed = true
	close(sess.done)
	if s.realms[sess.realmID] == sess {
		delete(s.realms, sess.realmID)
	}
	if _, ok := s.sessions[sess.id]; ok {
		s.ipCounts[sess.clientIP]--
		if s.ipCounts[sess.clientIP] <= 0 {
			delete(s.ipCounts, sess.clientIP)
		}
	}
	delete(s.sessions, sess.id)
	for nonce, ch := range sess.pending {
		close(ch)
		delete(sess.pending, nonce)
	}
}

func (s *server) removeExpiredSession(sess *session, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed || !now.After(sess.expires) {
		return false
	}
	s.removeSessionLocked(sess)
	return true
}

func (s *server) registerPending(sess *session, nonce string) (chan punchResponsePayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return nil, errSessionClosed
	}
	if _, exists := sess.pending[nonce]; exists {
		return nil, errNonceInUse
	}
	if len(sess.pending) >= maxPendingAttempts {
		return nil, errPendingFull
	}
	ch := make(chan punchResponsePayload, 1)
	sess.pending[nonce] = ch
	s.pendingConnects.Add(1)
	return ch, nil
}

func (s *server) deliverPending(sess *session, nonce string, payload punchResponsePayload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	ch, ok := sess.pending[nonce]
	if !ok {
		return false
	}
	delete(sess.pending, nonce)
	select {
	case ch <- payload:
	default:
	}
	return true
}

// cancelPending removes the pending entry that registerPending returned ch
// for. Once a response is delivered the nonce is free again, so a newer
// connect may already have registered it; that entry is left alone.
func (s *server) cancelPending(sess *session, nonce string, ch chan punchResponsePayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.pending[nonce] == ch {
		delete(sess.pending, nonce)
	}
	s.pendingConnects.Add(-1)
}

func (s *server) sendEvent(sess *session, ev sessionEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	ev.queued = time.Now()
	select {
	case sess.events <- ev:
		return true
	default:
		return false
	}
}

// requeueEvent puts back an event that a replaced stream received but did
// not write.
func (s *server) requeueEvent(sess *session, ev sessionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return
	}
	select {
	case sess.events <- ev:
	default:
	}
}

// sendAck queues a heartbeat_ack for the session's event stream. Acks are
// coalesced: while one is waiting to be written, another adds nothing.
func (s *server) sendAck(sess *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	select {
	case sess.ack <- struct{}{}:
	default:
	}
	return true
}

// attachStream makes a new /events stream the owner of sess and stops the
// stream that owned it before. A realm server only opens a new stream after
// it has given up on the old one, which is usually a connection that died
// without this server noticing; left running, it would keep taking events
// and writing them into the dead connection.
func (s *server) attachStream(parent context.Context, sess *session) (context.Context, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return nil, 0, false
	}
	if sess.streamCancel != nil {
		sess.streamCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	s.streamSeq++
	sess.stream = s.streamSeq
	sess.streamCancel = cancel
	return ctx, sess.stream, true
}

func (s *server) detachStream(sess *session, id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.stream != id {
		// Already replaced; the newer stream canceled this one.
		return
	}
	sess.streamCancel()
	sess.stream = 0
	sess.streamCancel = nil
}

func (s *server) reaper() {
	t := time.NewTicker(reaperInterval)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		now := time.Now()
		var expired []*session
		for _, sess := range s.sessions {
			if now.After(sess.expires) {
				expired = append(expired, sess)
			}
		}
		s.mu.Unlock()
		for _, sess := range expired {
			if s.removeExpiredSession(sess, now) {
				s.metrics.sessionExpired()
				debugf("session expired realm=%s session=%s", sess.realmID, sess.id)
			}
		}
		s.connectLimiter.prune(now)
	}
}
