package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

type punchEvent struct {
	Addresses []string `json:"addresses"`
	Nonce     string   `json:"nonce"`
	Obfs      string   `json:"obfs"`
}

const maxRequestBodyBytes = 4 << 10

var connectResponseTimeout = 10 * time.Second

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	if s.metrics != nil {
		r.Use(s.metrics.httpMiddleware)
	}
	r.Use(limitBody)
	r.Post("/v1/{id}", s.register)
	r.Delete("/v1/{id}", s.deregister)
	r.Get("/v1/{id}/events", s.events)
	r.Post("/v1/{id}/heartbeat", s.heartbeat)
	r.Post("/v1/{id}/connect", s.connect)
	r.Post("/v1/{id}/connects/{nonce}", s.connectResponse)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, errNotFound, "unknown path")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusMethodNotAllowed, errBadRequest, "method not allowed")
	})
	return r
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	s.routes().ServeHTTP(w, r)
}

func (s *server) checkRealmToken(r *http.Request) bool {
	expected := realmToken
	if expected == "" {
		return false
	}
	// Compare digests in constant time so response timing reveals
	// neither the token's contents nor its length.
	got := sha256.Sum256([]byte(bearer(r)))
	want := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (s *server) requestIP(r *http.Request) string {
	return clientIP(r, s.proxyHeader, s.trustedProxies)
}

func (s *server) realmID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	if !s.realmIDPattern.MatchString(id) {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid realm name")
		return "", false
	}
	return id, true
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		s.metrics.registration("bad_request")
		return
	}
	remote := s.requestIP(r)
	if !s.checkRealmToken(r) {
		debugf("register unauthorized realm=%s remote=%s", id, remote)
		s.metrics.registration("invalid_token")
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid realm token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.registration("bad_request")
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		s.metrics.registration("bad_request")
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}

	ip := remote
	s.mu.Lock()
	if _, exists := s.realms[id]; exists {
		s.mu.Unlock()
		debugf("register conflict realm=%s remote=%s", id, ip)
		s.metrics.registration("conflict")
		writeErr(w, http.StatusConflict, errRealmTaken, "realm already registered")
		return
	}
	if s.maxRealms > 0 && len(s.realms) >= s.maxRealms {
		s.mu.Unlock()
		debugf("register rejected (global limit) realm=%s remote=%s", id, ip)
		s.metrics.registration("global_limit")
		writeErr(w, http.StatusTooManyRequests, errRealmLimit, "global realm limit reached")
		return
	}
	if s.maxRealmsPerIP > 0 && s.ipCounts[ip] >= s.maxRealmsPerIP {
		s.mu.Unlock()
		debugf("register rejected (per-ip limit) realm=%s remote=%s", id, remote)
		s.metrics.registration("ip_limit")
		writeErr(w, http.StatusTooManyRequests, errIPLimit, "per-ip realm limit reached")
		return
	}
	sess := &session{
		id:        randToken(),
		realmID:   id,
		addresses: req.Addresses,
		expires:   time.Now().Add(sessionTTL),
		events:    make(chan sessionEvent, eventsBufferSize),
		ack:       make(chan struct{}, 1),
		done:      make(chan struct{}),
		clientIP:  ip,
		pending:   make(map[string]chan punchResponsePayload),
	}
	s.realms[id] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[ip]++
	s.mu.Unlock()
	debugf("registered realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(req.Addresses), ip)
	s.metrics.registration("ok")

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.id,
		"ttl":        int(sessionTTL.Seconds()),
	})
}

func (s *server) deregister(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	remote := s.requestIP(r)
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("deregister unauthorized realm=%s remote=%s", id, remote)
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	debugf("deregistered realm=%s session=%s remote=%s", id, sess.id, remote)
	s.removeSession(sess)
	s.metrics.deregistration()
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	remote := s.requestIP(r)
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("heartbeat unauthorized realm=%s remote=%s", id, remote)
		s.metrics.heartbeat("invalid_token")
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			s.metrics.heartbeat("bad_request")
			writeErr(w, http.StatusBadRequest, errBadRequest, "invalid json")
			return
		}
	}
	if req.Addresses != nil {
		if err := validateAddresses(req.Addresses); err != nil {
			s.metrics.heartbeat("bad_request")
			writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
			return
		}
	}
	s.mu.Lock()
	if sess.closed {
		s.mu.Unlock()
		debugf("heartbeat closed realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.heartbeat("invalid_token")
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	sess.expires = time.Now().Add(sessionTTL)
	if req.Addresses != nil {
		sess.addresses = append([]string(nil), req.Addresses...)
	}
	s.mu.Unlock()
	debugf("heartbeat realm=%s session=%s addressesUpdated=%t remote=%s", id, sess.id, req.Addresses != nil, remote)
	s.metrics.heartbeat("ok")
	if !s.sendAck(sess) {
		debugf("heartbeat ack dropped realm=%s session=%s remote=%s", id, sess.id, remote)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ttl": int(sessionTTL.Seconds())})
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	remote := s.requestIP(r)
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("events unauthorized realm=%s remote=%s", id, remote)
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeErr(w, http.StatusInternalServerError, errInternal, "streaming not supported")
		return
	}
	ctx, streamID, ok := s.attachStream(r.Context(), sess)
	if !ok {
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	defer s.detachStream(sess, streamID)
	debugf("events connected realm=%s session=%s remote=%s", id, sess.id, remote)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		debugf("events write failed realm=%s session=%s remote=%s err=%v", id, sess.id, remote, err)
		return
	}

	s.activeEventStreams.Add(1)
	defer s.activeEventStreams.Add(-1)

	for {
		var ev sessionEvent
		select {
		case <-ctx.Done():
			if r.Context().Err() == nil {
				debugf("events replaced by a newer stream realm=%s session=%s remote=%s", id, sess.id, remote)
			} else {
				debugf("events disconnected realm=%s session=%s remote=%s", id, sess.id, remote)
			}
			return
		case <-sess.done:
			debugf("events closed realm=%s session=%s remote=%s", id, sess.id, remote)
			return
		case <-sess.ack:
			ev = sessionEvent{kind: "heartbeat_ack", data: map[string]any{"ttl": int(sessionTTL.Seconds())}}
		case ev = <-sess.events:
		}
		if ctx.Err() != nil {
			// A newer stream took over while this one was picking up the
			// event. Hand it back so the new stream delivers it.
			if ev.kind == "heartbeat_ack" {
				s.sendAck(sess)
			} else {
				s.requeueEvent(sess, ev)
			}
			return
		}
		if ev.kind == "punch" && time.Since(ev.queued) > punchEventMaxAge {
			debugf("events dropped stale punch realm=%s session=%s age=%s", id, sess.id, time.Since(ev.queued).Round(time.Second))
			continue
		}
		if err := writeSSE(w, rc, ev); err != nil {
			debugf("events write failed realm=%s session=%s remote=%s err=%v", id, sess.id, remote, err)
			return
		}
	}
}

func writeSSE(w io.Writer, rc *http.ResponseController, ev sessionEvent) error {
	data, err := json.Marshal(ev.data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.kind, data); err != nil {
		return err
	}
	return rc.Flush()
}

func (s *server) connect(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	remote := s.requestIP(r)
	if !s.checkRealmToken(r) {
		debugf("connect unauthorized realm=%s remote=%s", id, remote)
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid realm token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
		Nonce     string   `json:"nonce"`
		Obfs      string   `json:"obfs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	if err := validateHexField("nonce", req.Nonce, nonceHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	if err := validateHexField("obfs", req.Obfs, obfsHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	s.metrics.connectRequest()

	if !s.connectLimiter.allow(remote, time.Now()) {
		debugf("connect rate limited (per-ip) realm=%s remote=%s", id, remote)
		s.metrics.connectOutcome("ip_rate_limited")
		writeErr(w, http.StatusTooManyRequests, errRateLimited, "too many connect requests from this address")
		return
	}

	s.mu.Lock()
	sess := s.realms[id]
	if sess == nil || sess.closed || time.Now().After(sess.expires) {
		s.mu.Unlock()
		debugf("connect realm not found realm=%s remote=%s", id, remote)
		s.metrics.connectOutcome("no_realm")
		writeErr(w, http.StatusNotFound, errRealmNotFound, "realm not registered")
		return
	}
	serverAddrs := append([]string(nil), sess.addresses...)
	s.mu.Unlock()

	// Register the pending entry BEFORE pushing the punch event,
	// so a fast Hysteria server can never deliver before we're ready.
	respCh, err := s.registerPending(sess, req.Nonce)
	switch {
	case errors.Is(err, errSessionClosed):
		debugf("connect realm not found realm=%s remote=%s", id, remote)
		s.metrics.connectOutcome("no_realm")
		writeErr(w, http.StatusNotFound, errRealmNotFound, "realm not registered")
		return
	case errors.Is(err, errNonceInUse):
		debugf("connect nonce in use realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.connectOutcome("nonce_in_use")
		writeErr(w, http.StatusConflict, errAttemptExists, "a connect attempt with this nonce is already in flight")
		return
	case err != nil:
		debugf("connect rate limited (pending) realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.connectOutcome("rate_limited")
		writeErr(w, http.StatusServiceUnavailable, errRateLimited, "too many in-flight connect attempts")
		return
	}
	defer s.cancelPending(sess, req.Nonce, respCh)

	if s.sendEvent(sess, sessionEvent{kind: "punch", data: punchEvent{Addresses: req.Addresses, Nonce: req.Nonce, Obfs: req.Obfs}}) {
		debugf("connect notified realm=%s session=%s clientAddresses=%d serverAddresses=%d remote=%s", id, sess.id, len(req.Addresses), len(serverAddrs), remote)
	} else {
		debugf("connect rate limited realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.connectOutcome("rate_limited")
		writeErr(w, http.StatusServiceUnavailable, errRateLimited, "server event buffer full")
		return
	}

	// Now we wait for the fresh addresses to arrive.
	waitStart := time.Now()
	timer := time.NewTimer(connectResponseTimeout)
	defer timer.Stop()
	select {
	case payload, ok := <-respCh:
		if !ok {
			debugf("connect canceled realm=%s session=%s remote=%s", id, sess.id, remote)
			s.metrics.connectOutcome("canceled")
			writeErr(w, http.StatusNotFound, errRealmNotFound, "realm not registered")
			return
		}
		if len(payload.addresses) > 0 {
			serverAddrs = payload.addresses
			debugf("connect fresh addresses realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(serverAddrs), remote)
		}
		s.metrics.observeConnect(time.Since(waitStart))
		s.metrics.connectOutcome("delivered")
	case <-timer.C:
		debugf("connect response timed out realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.connectOutcome("timeout")
	case <-sess.done:
		debugf("connect canceled realm=%s session=%s remote=%s", id, sess.id, remote)
		s.metrics.connectOutcome("canceled")
		writeErr(w, http.StatusNotFound, errRealmNotFound, "realm not registered")
		return
	case <-r.Context().Done():
		// Client gave up
		s.metrics.connectOutcome("client_gave_up")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"addresses": serverAddrs,
		"nonce":     req.Nonce,
		"obfs":      req.Obfs,
	})
}

func (s *server) connectResponse(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	remote := s.requestIP(r)
	nonce := chi.URLParam(r, "nonce")
	if err := validateHexField("nonce", nonce, nonceHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("connect-response unauthorized realm=%s remote=%s", id, remote)
		writeErr(w, http.StatusUnauthorized, errInvalidToken, "invalid session token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	if !s.deliverPending(sess, nonce, punchResponsePayload{addresses: req.Addresses}) {
		debugf("connect-response no pending realm=%s session=%s nonce=%s remote=%s", id, sess.id, nonce, remote)
		s.metrics.connectResponse("no_pending")
		writeErr(w, http.StatusNotFound, errAttemptNotFound, "no pending attempt for nonce")
		return
	}
	debugf("connect-response delivered realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(req.Addresses), remote)
	s.metrics.connectResponse("delivered")
	w.WriteHeader(http.StatusNoContent)
}
