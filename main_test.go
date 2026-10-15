package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRealmToken = "realm-token"
	testNonce      = "00112233445566778899aabbccddeeff"
	testObfs       = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

func TestMain(m *testing.M) {
	// Shrink the connect-response wait so tests that don't post a response
	// (i.e. exercise the fallback path) finish quickly. The new tests that
	// explicitly exercise the wait/respond path override this further.
	connectResponseTimeout = 100 * time.Millisecond
	os.Exit(m.Run())
}

func TestConnectForwardsPunchMetadata(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	eventsCtx, cancelEvents := context.WithCancel(context.Background())
	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil).WithContext(eventsCtx)
	eventsReq.Header.Set("Authorization", "Bearer "+registerBody.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"198.51.100.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, want %d", connectResp.Code, http.StatusOK)
	}
	var connectBody struct {
		Addresses []string `json:"addresses"`
		Nonce     string   `json:"nonce"`
		Obfs      string   `json:"obfs"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&connectBody); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(connectBody.Addresses, ","), "203.0.113.10:4433"; got != want {
		t.Fatalf("connect addresses = %q, want %q", got, want)
	}
	if connectBody.Nonce != testNonce {
		t.Fatalf("connect nonce = %q, want %q", connectBody.Nonce, testNonce)
	}
	if connectBody.Obfs != testObfs {
		t.Fatalf("connect obfs = %q, want %q", connectBody.Obfs, testObfs)
	}

	waitForSSEData(t, eventsResp)
	cancelEvents()
	<-eventsDone

	scanner := bufio.NewScanner(eventsResp.Body)
	var eventData string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			eventData = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if eventData == "" {
		t.Fatal("missing SSE data line")
	}
	var ev punchEvent
	if err := json.Unmarshal([]byte(eventData), &ev); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(ev.Addresses, ","), "198.51.100.20:4433"; got != want {
		t.Fatalf("event addresses = %q, want %q", got, want)
	}
	if ev.Nonce != testNonce {
		t.Fatalf("event nonce = %q, want %q", ev.Nonce, testNonce)
	}
	if ev.Obfs != testObfs {
		t.Fatalf("event obfs = %q, want %q", ev.Obfs, testObfs)
	}
}

func TestConnectRequiresPunchMetadata(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}

	tests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing nonce",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"obfs":      testObfs,
			},
		},
		{
			name: "invalid nonce",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     "not-hex",
				"obfs":      testObfs,
			},
		},
		{
			name: "missing obfs",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     testNonce,
			},
		},
		{
			name: "invalid obfs",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     testNonce,
				"obfs":      "not-hex",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, tc.body)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("connect status = %d, want %d", resp.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHeartbeatUpdatesAddresses(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	heartbeatResp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{
		"addresses": []string{"203.0.113.11:4433"},
	})
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d", heartbeatResp.Code, http.StatusOK)
	}

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"198.51.100.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, want %d", connectResp.Code, http.StatusOK)
	}
	var connectBody struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&connectBody); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(connectBody.Addresses, ","), "203.0.113.11:4433"; got != want {
		t.Fatalf("connect addresses = %q, want %q", got, want)
	}
}

func TestHeartbeatRejectsInvalidAddresses(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	resp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{
		"addresses": []string{"not-an-address"},
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("heartbeat status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func TestHeartbeatPushesAckEvent(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	eventsCtx, cancelEvents := context.WithCancel(context.Background())
	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil).WithContext(eventsCtx)
	eventsReq.Header.Set("Authorization", "Bearer "+registerBody.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	hbResp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{})
	if hbResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d", hbResp.Code)
	}

	waitForSSEData(t, eventsResp)
	cancelEvents()
	<-eventsDone

	body := eventsResp.Body.String()
	if !strings.Contains(body, "event: heartbeat_ack") {
		t.Fatalf("missing heartbeat_ack event in stream: %q", body)
	}
	if !strings.Contains(body, `"ttl":60`) {
		t.Fatalf("heartbeat_ack data missing ttl: %q", body)
	}
}

func TestConnectWaitsForResponse(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	// Make sure the wait is long enough for the goroutine below to run.
	old := connectResponseTimeout
	connectResponseTimeout = 2 * time.Second
	t.Cleanup(func() { connectResponseTimeout = old })

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	// Post the connect-response from a separate goroutine while /connect is
	// still waiting. Use a fresh address list to assert the response wins
	// over the registered cache.
	freshAddrs := []string{"198.51.100.1:9999"}
	go func() {
		// Small jitter to make sure /connect is already waiting on the channel.
		time.Sleep(50 * time.Millisecond)
		body, _ := json.Marshal(map[string]any{"addresses": freshAddrs})
		req := httptest.NewRequest(http.MethodPost, "/v1/example/connects/"+testNonce, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rb.SessionID)
		resp := httptest.NewRecorder()
		s.handle(resp, req)
		if resp.Code != http.StatusNoContent {
			t.Errorf("connect-response status = %d, body = %s", resp.Code, resp.Body.String())
		}
	}()

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", connectResp.Code, connectResp.Body.String())
	}
	var cb struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&cb); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cb.Addresses, ","), strings.Join(freshAddrs, ","); got != want {
		t.Fatalf("addresses = %q, want %q (fresh from connect-response)", got, want)
	}
}

func TestConnectFallsBackOnTimeout(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registered := []string{"203.0.113.10:4433"}
	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": registered,
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}

	// No connect-response goroutine; connect must time out and return cached.
	start := time.Now()
	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	elapsed := time.Since(start)
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d", connectResp.Code)
	}
	if elapsed < connectResponseTimeout {
		t.Fatalf("returned in %v, want >= %v", elapsed, connectResponseTimeout)
	}
	if elapsed > connectResponseTimeout+time.Second {
		t.Fatalf("returned in %v, well past %v", elapsed, connectResponseTimeout)
	}
	var cb struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&cb); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cb.Addresses, ","), strings.Join(registered, ","); got != want {
		t.Fatalf("addresses = %q, want %q (registered cache)", got, want)
	}
}

func TestConnectResponseNotFoundForUnknownNonce(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	// No /connect call has happened, so this nonce has no pending entry.
	body, _ := json.Marshal(map[string]any{"addresses": []string{"198.51.100.1:9999"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/example/connects/"+testNonce, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rb.SessionID)
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&er)
	if er.Error != "attempt_not_found" {
		t.Fatalf("error code = %q, want attempt_not_found", er.Error)
	}
}

func TestEventsStreamClosesOnDeregister(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil)
	eventsReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	select {
	case <-eventsResp.flushed:
	case <-time.After(time.Second):
		t.Fatal("events stream did not start")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/example", nil)
	delReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	delResp := httptest.NewRecorder()
	s.handle(delResp, delReq)
	if delResp.Code != http.StatusNoContent {
		t.Fatalf("deregister status = %d", delResp.Code)
	}

	select {
	case <-eventsDone:
	case <-time.After(time.Second):
		t.Fatal("events stream did not close after deregister")
	}
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("events status = %d", eventsResp.Code)
	}
}

func TestSendEventAfterRemoveSessionFails(t *testing.T) {
	s := newServer(serverConfig{})
	sess := &session{
		id:       "session",
		realmID:  "example",
		events:   make(chan sessionEvent, 1),
		done:     make(chan struct{}),
		clientIP: "1.1.1.1",
		pending:  make(map[string]chan punchResponsePayload),
	}
	s.realms[sess.realmID] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[sess.clientIP] = 1

	s.removeSession(sess)
	if s.sendEvent(sess, sessionEvent{kind: "test"}) {
		t.Fatal("sendEvent succeeded on a removed session")
	}
}

func TestRemoveExpiredSessionRechecksExpiration(t *testing.T) {
	s := newServer(serverConfig{})
	now := time.Now()
	sess := &session{
		id:       "session",
		realmID:  "example",
		expires:  now.Add(time.Second),
		events:   make(chan sessionEvent, 1),
		done:     make(chan struct{}),
		clientIP: "1.1.1.1",
		pending:  make(map[string]chan punchResponsePayload),
	}
	s.realms[sess.realmID] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[sess.clientIP] = 1

	if s.removeExpiredSession(sess, now) {
		t.Fatal("removed a session that was refreshed after the reaper scan")
	}
	if sess.closed {
		t.Fatal("session was closed")
	}
	if s.sessions[sess.id] == nil {
		t.Fatal("session was removed from index")
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	body := bytes.Repeat([]byte("a"), maxRequestBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/example", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	resp := httptest.NewRecorder()
	s.handle(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func registerWith(t *testing.T, s *server, realm, remoteAddr, header, headerValue string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"addresses": []string{"203.0.113.10:4433"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/"+realm, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if header != "" {
		req.Header.Set(header, headerValue)
	}
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	return resp.Code
}

func TestGlobalRealmLimit(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealms: 2})

	if c := registerWith(t, s, "a", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("first = %d", c)
	}
	if c := registerWith(t, s, "b", "2.2.2.2:1", "", ""); c != http.StatusOK {
		t.Fatalf("second = %d", c)
	}
	if c := registerWith(t, s, "c", "3.3.3.3:1", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("third = %d, want 429", c)
	}
}

func TestPerIPRealmLimit(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 2})

	if c := registerWith(t, s, "a", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("a = %d", c)
	}
	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusOK {
		t.Fatalf("b = %d", c)
	}
	if c := registerWith(t, s, "c", "1.1.1.1:3", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("c = %d, want 429", c)
	}
	if c := registerWith(t, s, "d", "2.2.2.2:1", "", ""); c != http.StatusOK {
		t.Fatalf("different IP d = %d", c)
	}
}

func TestPerIPRealmLimitViaProxyHeader(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 1, proxyHeader: "X-Forwarded-For"})

	if c := registerWith(t, s, "a", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.5"); c != http.StatusOK {
		t.Fatalf("a = %d", c)
	}
	// The proxy appends the address it saw, so the rightmost entry is the
	// client. Whatever the client put further left does not matter.
	if c := registerWith(t, s, "b", "10.0.0.1:1", "X-Forwarded-For", "198.51.100.1, 203.0.113.5"); c != http.StatusTooManyRequests {
		t.Fatalf("b = %d, want 429", c)
	}
	if c := registerWith(t, s, "c", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.5, 203.0.113.6"); c != http.StatusOK {
		t.Fatalf("c = %d", c)
	}
}

func TestPerIPRealmLimitViaProxyHeaderWithTrustedProxies(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{
		maxRealmsPerIP: 1,
		proxyHeader:    "X-Forwarded-For",
		trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})

	// Two proxy hops: the client's address is the rightmost one that is
	// not a trusted proxy.
	if c := registerWith(t, s, "a", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.5, 10.0.0.2"); c != http.StatusOK {
		t.Fatalf("a = %d", c)
	}
	if c := registerWith(t, s, "b", "10.0.0.1:1", "X-Forwarded-For", "1.1.1.1, 203.0.113.5, 10.0.0.2"); c != http.StatusTooManyRequests {
		t.Fatalf("b = %d, want 429", c)
	}
	// A request that does not come from a trusted proxy cannot pick its
	// address with the header.
	if c := registerWith(t, s, "c", "203.0.113.9:1", "X-Forwarded-For", "198.51.100.7"); c != http.StatusOK {
		t.Fatalf("c = %d", c)
	}
	if c := registerWith(t, s, "d", "203.0.113.9:1", "X-Forwarded-For", "198.51.100.8"); c != http.StatusTooManyRequests {
		t.Fatalf("d = %d, want 429 (header from an untrusted peer must be ignored)", c)
	}
}

func TestPerIPLimitDecrementsOnDeregister(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 1})

	body, _ := json.Marshal(map[string]any{"addresses": []string{"203.0.113.10:4433"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/a", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	req.RemoteAddr = "1.1.1.1:1"
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("register = %d", resp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rb)

	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("expected 429 before deregister, got %d", c)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/a", nil)
	delReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	delReq.RemoteAddr = "1.1.1.1:1"
	delResp := httptest.NewRecorder()
	s.handle(delResp, delReq)
	if delResp.Code != http.StatusNoContent {
		t.Fatalf("deregister = %d", delResp.Code)
	}

	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusOK {
		t.Fatalf("expected OK after deregister, got %d", c)
	}
}

func TestRealmNameValidation(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	cases := []struct {
		name string
		want int
	}{
		{"good", http.StatusOK},
		{"-leading-hyphen", http.StatusBadRequest},
		{"_leading-underscore", http.StatusBadRequest},
		{"has.dot", http.StatusBadRequest},
		{"has%20space", http.StatusBadRequest},
		{strings.Repeat("a", 65), http.StatusBadRequest},
		{"unicode-%C3%B1", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := registerWith(t, s, tc.name, "1.1.1.1:1", "", "")
			if c != tc.want {
				t.Fatalf("status = %d, want %d", c, tc.want)
			}
		})
	}
}

func TestRealmNameCustomPattern(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{realmIDPattern: regexp.MustCompile(`^[0-9]+$`)})

	if c := registerWith(t, s, "12345", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("digits = %d", c)
	}
	if c := registerWith(t, s, "abc", "1.1.1.1:2", "", ""); c != http.StatusBadRequest {
		t.Fatalf("letters = %d, want 400", c)
	}
}

func TestGetenvBool(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "true")
	if b, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST", false); err != nil || !b {
		t.Fatalf("got %v, %v; want true", b, err)
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "1")
	if b, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST", false); err != nil || !b {
		t.Fatalf("got %v, %v; want true for 1", b, err)
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "Yes")
	if b, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST", false); err != nil || !b {
		t.Fatalf("got %v, %v; want true for Yes", b, err)
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "off")
	if b, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST", true); err != nil || b {
		t.Fatalf("got %v, %v; want false for off", b, err)
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "nope")
	if _, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST", true); err == nil {
		t.Fatal("expected an error for an invalid bool")
	}
	if b, err := getenvBool("HYSTERIA_REALM_DEBUG_TEST_UNSET", false); err != nil || b {
		t.Fatalf("got %v, %v; want default false for unset", b, err)
	}
	_ = os.Unsetenv("HYSTERIA_REALM_DEBUG_TEST_UNSET")
}

func TestParseConfigEnvDefaults(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_LISTEN", ":9443")
	t.Setenv("HYSTERIA_REALM_TOKEN", "env-token")
	t.Setenv("HYSTERIA_REALM_CERT", "env.crt")
	t.Setenv("HYSTERIA_REALM_KEY", "env.key")
	t.Setenv("HYSTERIA_REALM_DEBUG", "true")

	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9443" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.Token != "env-token" {
		t.Fatalf("token = %q", cfg.Token)
	}
	if cfg.Cert != "env.crt" {
		t.Fatalf("cert = %q", cfg.Cert)
	}
	if cfg.Key != "env.key" {
		t.Fatalf("key = %q", cfg.Key)
	}
	if !cfg.Debug {
		t.Fatal("debug = false")
	}
}

func TestParseConfigFlagsOverrideEnv(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_LISTEN", ":9443")
	t.Setenv("HYSTERIA_REALM_TOKEN", "env-token")
	t.Setenv("HYSTERIA_REALM_CERT", "env.crt")
	t.Setenv("HYSTERIA_REALM_KEY", "env.key")
	t.Setenv("HYSTERIA_REALM_DEBUG", "false")

	cfg, err := parseConfig([]string{
		"--listen", ":10443",
		"--token", "flag-token",
		"--cert", "flag.crt",
		"--key", "flag.key",
		"--debug",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":10443" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.Token != "flag-token" {
		t.Fatalf("token = %q", cfg.Token)
	}
	if cfg.Cert != "flag.crt" {
		t.Fatalf("cert = %q", cfg.Cert)
	}
	if cfg.Key != "flag.key" {
		t.Fatalf("key = %q", cfg.Key)
	}
	if !cfg.Debug {
		t.Fatal("debug = false")
	}
}

func TestNewEventStreamReplacesOldOne(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	sid := registerRealm(t, s, "example")

	oldRec := newFlushRecorder()
	cancelOld, oldDone := openEvents(t, s, "example", sid, oldRec, oldRec)
	defer cancelOld()
	newRec := newFlushRecorder()
	cancelNew, newDone := openEvents(t, s, "example", sid, newRec, newRec)
	defer cancelNew()

	// The old stream's client never disconnected, as with a connection
	// that died silently. The new stream still takes over.
	waitClosed(t, oldDone, "the replaced stream to stop")

	if resp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, connectBody(testNonce)); resp.Code != http.StatusOK {
		t.Fatalf("connect status = %d", resp.Code)
	}
	if resp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", sid, map[string]any{}); resp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d", resp.Code)
	}
	waitForBody(t, newRec, "event: punch", 1)
	waitForBody(t, newRec, "event: heartbeat_ack", 1)
	if body := oldRec.body(); strings.Contains(body, "event:") {
		t.Fatalf("replaced stream received events: %q", body)
	}
	cancelNew()
	waitClosed(t, newDone, "the stream to stop")
}

func TestHeartbeatAcksDoNotFillEventBuffer(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	sid := registerRealm(t, s, "example")

	// With no stream reading, acks used to pile up in the event buffer
	// until every connect failed with 503.
	for i := 0; i < 2*eventsBufferSize; i++ {
		if resp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", sid, map[string]any{}); resp.Code != http.StatusOK {
			t.Fatalf("heartbeat %d status = %d", i, resp.Code)
		}
	}
	if resp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, connectBody(testNonce)); resp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", resp.Code, resp.Body.String())
	}

	rec := newFlushRecorder()
	cancel, done := openEvents(t, s, "example", sid, rec, rec)
	waitForBody(t, rec, "event: punch", 1)
	waitForBody(t, rec, "event: heartbeat_ack", 1)
	cancel()
	waitClosed(t, done, "the stream to stop")
	if n := strings.Count(rec.Body.String(), "event: heartbeat_ack"); n != 1 {
		t.Fatalf("got %d heartbeat_ack events, want 1", n)
	}
}

func TestStalePunchEventsAreDropped(t *testing.T) {
	realmToken = testRealmToken
	oldMaxAge := punchEventMaxAge
	punchEventMaxAge = 10 * time.Millisecond
	t.Cleanup(func() { punchEventMaxAge = oldMaxAge })
	s := newServer(serverConfig{})
	sid := registerRealm(t, s, "example")

	// Nobody is listening, so the connect times out and its punch event
	// waits in the queue until it is older than punchEventMaxAge.
	if resp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, connectBody(testNonce)); resp.Code != http.StatusOK {
		t.Fatalf("connect status = %d", resp.Code)
	}
	s.mu.Lock()
	sess := s.realms["example"]
	s.mu.Unlock()

	rec := newFlushRecorder()
	cancel, done := openEvents(t, s, "example", sid, rec, rec)
	waitFor(t, func() bool { return len(sess.events) == 0 }, "the stream to take the queued event")
	// The stream handles events in order, so once this ack is written the
	// punch event has been dealt with.
	doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", sid, map[string]any{})
	waitForBody(t, rec, "event: heartbeat_ack", 1)
	cancel()
	waitClosed(t, done, "the stream to stop")
	if strings.Contains(rec.Body.String(), "event: punch") {
		t.Fatalf("stale punch event was delivered: %q", rec.Body.String())
	}
}

func TestEventsStreamStopsOnWriteError(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	sid := registerRealm(t, s, "example")

	rec := newFlushRecorder()
	cancel, done := openEvents(t, s, "example", sid, failingWriter{rec}, rec)
	defer cancel()
	doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", sid, map[string]any{})
	// The request context is never canceled: the failed write alone has
	// to end the stream.
	waitClosed(t, done, "the stream to stop after a failed write")
}

func TestEventsStreamWithMetricsEnabled(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	s.metrics = newMetrics()
	sid := registerRealm(t, s, "example")

	rec := newFlushRecorder()
	cancel, done := openEvents(t, s, "example", sid, rec, rec)
	doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", sid, map[string]any{})
	waitForBody(t, rec, "event: heartbeat_ack", 1)
	cancel()
	waitClosed(t, done, "the stream to stop")
}

// failingWriter is a stream whose connection is gone: every write fails.
type failingWriter struct{ *flushRecorder }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestDuplicateNonceIsRejected(t *testing.T) {
	realmToken = testRealmToken
	oldTimeout := connectResponseTimeout
	connectResponseTimeout = 2 * time.Second
	t.Cleanup(func() { connectResponseTimeout = oldTimeout })
	s := newServer(serverConfig{})
	sid := registerRealm(t, s, "example")

	first := connectAsync(s, "example", testNonce)
	waitFor(t, func() bool { return s.pendingConnects.Load() == 1 }, "the first connect to be pending")

	dup := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, connectBody(testNonce))
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", dup.Code, http.StatusConflict)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(dup.Body).Decode(&er)
	if er.Error != errAttemptExists {
		t.Fatalf("error code = %q, want %q", er.Error, errAttemptExists)
	}

	// The first attempt is unaffected.
	resp := doRequest(t, s, http.MethodPost, "/v1/example/connects/"+testNonce, sid, map[string]any{
		"addresses": []string{"198.51.100.1:9999"},
	})
	if resp.Code != http.StatusNoContent {
		t.Fatalf("connect-response status = %d", resp.Code)
	}
	select {
	case r := <-first:
		if r.Code != http.StatusOK {
			t.Fatalf("first connect status = %d", r.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first connect did not finish")
	}
}

func TestCancelPendingKeepsNewerAttempt(t *testing.T) {
	s := newServer(serverConfig{})
	sess := &session{
		id:      "session",
		realmID: "example",
		done:    make(chan struct{}),
		pending: make(map[string]chan punchResponsePayload),
	}
	first, err := s.registerPending(sess, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !s.deliverPending(sess, testNonce, punchResponsePayload{}) {
		t.Fatal("deliverPending failed")
	}
	// Delivery frees the nonce, and a newer connect takes it before the
	// first connect has cleaned up.
	second, err := s.registerPending(sess, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	s.cancelPending(sess, testNonce, first)
	if sess.pending[testNonce] != second {
		t.Fatal("cleaning up the first attempt removed the second attempt")
	}
	s.cancelPending(sess, testNonce, second)
	if len(sess.pending) != 0 {
		t.Fatalf("pending = %d entries, want 0", len(sess.pending))
	}
	if n := s.pendingConnects.Load(); n != 0 {
		t.Fatalf("pendingConnects = %d, want 0", n)
	}
}

func TestConnectRateLimitPerIP(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{connectRatePerIP: 2})

	// The realm does not exist, so allowed requests fail fast with 404.
	// They still count toward the limit.
	for i := 0; i < 2; i++ {
		if resp := doRequest(t, s, http.MethodPost, "/v1/missing/connect", testRealmToken, connectBody(testNonce)); resp.Code != http.StatusNotFound {
			t.Fatalf("request %d status = %d, want 404", i, resp.Code)
		}
	}
	resp := doRequest(t, s, http.MethodPost, "/v1/missing/connect", testRealmToken, connectBody(testNonce))
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.Code)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&er)
	if er.Error != errRateLimited {
		t.Fatalf("error code = %q, want %q", er.Error, errRateLimited)
	}

	// Another address has its own budget.
	body, _ := json.Marshal(connectBody(testNonce))
	req := httptest.NewRequest(http.MethodPost, "/v1/missing/connect", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	req.RemoteAddr = "198.51.100.50:1234"
	other := httptest.NewRecorder()
	s.handle(other, req)
	if other.Code != http.StatusNotFound {
		t.Fatalf("other address status = %d, want 404", other.Code)
	}
}

func TestIPRateLimiter(t *testing.T) {
	l := newIPRateLimiter(60, 2) // one token per second, bursts of 2
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) {
		t.Fatal("burst was limited")
	}
	if l.allow("a", now) {
		t.Fatal("third request in the same instant was allowed")
	}
	if !l.allow("b", now) {
		t.Fatal("another IP shared the first IP's bucket")
	}
	if !l.allow("a", now.Add(time.Second)) {
		t.Fatal("no token after a second")
	}
	l.prune(now.Add(time.Minute))
	if len(l.buckets) != 0 {
		t.Fatalf("prune kept %d full buckets", len(l.buckets))
	}
	if newIPRateLimiter(0, 10) != nil {
		t.Fatal("a rate of 0 should mean no limiter")
	}
	var unlimited *ipRateLimiter
	if !unlimited.allow("a", now) {
		t.Fatal("nil limiter refused a request")
	}
}

func TestValidateAddresses(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1:22",
		"[::1]:443",
		"0.0.0.0:443",
		"[::]:443",
		"224.0.0.1:5353",
		"[ff02::1]:5353",
		"255.255.255.255:9",
		"169.254.1.1:443",
		"[fe80::1]:443",
		"[fe80::1%eth0]:443",
		"[::ffff:127.0.0.1]:22",
		"203.0.113.10:0",
	} {
		if err := validateAddresses([]string{a}); err == nil {
			t.Errorf("%s was accepted", a)
		}
	}
	for _, a := range []string{
		"203.0.113.10:4433",
		"[2001:db8::1]:4433",
		"192.168.1.10:4433",
		"10.0.0.5:4433",
		"100.64.0.1:4433",
	} {
		if err := validateAddresses([]string{a}); err != nil {
			t.Errorf("%s was rejected: %v", a, err)
		}
	}
}

func TestRegisterRejectsLoopbackAddress(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	resp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"127.0.0.1:4433"},
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.Code)
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name    string
		remote  string
		header  string
		values  []string
		trusted []netip.Prefix
		want    string
	}{
		{name: "no header configured", remote: "203.0.113.1:5", values: []string{"1.1.1.1"}, want: "203.0.113.1"},
		{name: "header missing", remote: "10.0.0.1:5", header: "X-Forwarded-For", want: "10.0.0.1"},
		{name: "rightmost entry wins", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"1.1.1.1, 203.0.113.99"}, want: "203.0.113.99"},
		{name: "entry with port", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"[2001:db8::5]:1234"}, want: "2001:db8::5"},
		{name: "malformed rightmost entry", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"1.1.1.1, nonsense"}, want: "10.0.0.1"},
		{name: "multiple header lines", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"1.1.1.1", "203.0.113.7"}, want: "203.0.113.7"},
		{name: "untrusted peer", remote: "203.0.113.9:5", header: "X-Forwarded-For", values: []string{"1.1.1.1"}, trusted: trusted, want: "203.0.113.9"},
		{name: "skips trusted hops", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"1.1.1.1, 203.0.113.5, 10.0.0.2"}, trusted: trusted, want: "203.0.113.5"},
		{name: "all hops trusted", remote: "10.0.0.1:5", header: "X-Forwarded-For", values: []string{"10.0.0.3, 10.0.0.2"}, trusted: trusted, want: "10.0.0.3"},
		{name: "mapped IPv4 socket address", remote: "[::ffff:192.0.2.1]:5", want: "192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.values {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r, tc.header, tc.trusted); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckRealmToken(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})
	cases := map[string]bool{
		testRealmToken:       true,
		"":                   false,
		"realm":              false,
		testRealmToken + "x": false,
		"Realm-token":        false,
	}
	for token, want := range cases {
		r := httptest.NewRequest(http.MethodPost, "/v1/example", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if got := s.checkRealmToken(r); got != want {
			t.Errorf("token %q: got %v, want %v", token, got, want)
		}
	}
}

func TestParseConfigRejectsInvalidEnvValues(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_TOKEN", "token")
	t.Setenv("HYSTERIA_REALM_MAX_REALMS_PER_IP", "ten")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("accepted a non-numeric HYSTERIA_REALM_MAX_REALMS_PER_IP")
	}
	t.Setenv("HYSTERIA_REALM_MAX_REALMS_PER_IP", "")
	t.Setenv("HYSTERIA_REALM_DEBUG", "maybe")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("accepted a non-boolean HYSTERIA_REALM_DEBUG")
	}
}

func TestParseConfigRequiresCertAndKeyTogether(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_TOKEN", "token")
	if _, err := parseConfig([]string{"--cert", "a.crt"}); err == nil {
		t.Fatal("accepted a certificate without a key")
	}
	if _, err := parseConfig([]string{"--key", "a.key"}); err == nil {
		t.Fatal("accepted a key without a certificate")
	}
	if _, err := parseConfig([]string{"--cert", "a.crt", "--key", "a.key"}); err != nil {
		t.Fatal(err)
	}
}

func TestParseConfigRequiresToken(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_TOKEN", "")
	t.Setenv("HYSTERIA_REALM_TOKEN_FILE", "")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("accepted a config without a token")
	}
}

func TestParseConfigTokenFile(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_TOKEN", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]string{"--token-file", path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "file-token" {
		t.Fatalf("token = %q, want %q", cfg.Token, "file-token")
	}
	if _, err := parseConfig([]string{"--token-file", path, "--token", "other"}); err == nil {
		t.Fatal("accepted both a token and a token file")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig([]string{"--token-file", empty}); err == nil {
		t.Fatal("accepted an empty token file")
	}
}

func TestParseConfigRejectsNegativeLimits(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_TOKEN", "token")
	for _, arg := range []string{"--max-realms=-1", "--max-realms-per-ip=-1", "--connect-rate-per-ip=-1"} {
		if _, err := parseConfig([]string{arg}); err == nil {
			t.Errorf("accepted %s", arg)
		}
	}
}

func TestCompileRealmNamePatternMatchesWholeName(t *testing.T) {
	re, err := compileRealmNamePattern(`[a-z]+`)
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("abc") {
		t.Fatal("pattern did not match abc")
	}
	for _, name := range []string{"abc1", "1abc", "ABC"} {
		if re.MatchString(name) {
			t.Errorf("pattern matched %q", name)
		}
	}
	if _, err := compileRealmNamePattern(`(`); err == nil {
		t.Fatal("accepted an invalid pattern")
	}
}

func TestServerConfigTrustedProxies(t *testing.T) {
	cfg := config{
		RealmNamePattern:   defaultRealmNamePattern,
		TrustedProxyHeader: "X-Forwarded-For",
		TrustedProxies:     "10.0.0.0/8, 192.0.2.1",
	}
	sc, err := cfg.serverConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.1/32")}
	if len(sc.trustedProxies) != len(want) || sc.trustedProxies[0] != want[0] || sc.trustedProxies[1] != want[1] {
		t.Fatalf("trusted proxies = %v, want %v", sc.trustedProxies, want)
	}
	cfg.TrustedProxies = "nonsense"
	if _, err := cfg.serverConfig(); err == nil {
		t.Fatal("accepted an invalid trusted proxy")
	}
	cfg.TrustedProxies = "10.0.0.0/8"
	cfg.TrustedProxyHeader = ""
	if _, err := cfg.serverConfig(); err == nil {
		t.Fatal("accepted trusted proxies without a trusted proxy header")
	}
}

// connectAsync sends a connect request from another goroutine. It does not
// use t, since t.Fatal must only be called from the test goroutine.
func connectAsync(s *server, realm, nonce string) <-chan *httptest.ResponseRecorder {
	out := make(chan *httptest.ResponseRecorder, 1)
	body, _ := json.Marshal(connectBody(nonce))
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/"+realm+"/connect", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testRealmToken)
		resp := httptest.NewRecorder()
		s.handle(resp, req)
		out <- resp
	}()
	return out
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func doRequest(t *testing.T, s *server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	bs, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(bs))
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	return resp
}

func waitForSSEData(t *testing.T, resp *flushRecorder) {
	t.Helper()
	select {
	case <-resp.wrote:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE data")
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex // guards the body while a handler is writing
	flushed chan struct{}
	wrote   chan struct{}
	once    sync.Once
	write   sync.Once
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}),
		wrote:            make(chan struct{}),
	}
}

func (r *flushRecorder) Flush() {
	r.mu.Lock()
	r.ResponseRecorder.Flush()
	r.mu.Unlock()
	r.once.Do(func() {
		close(r.flushed)
	})
}

func (r *flushRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	n, err := r.ResponseRecorder.Write(b)
	r.mu.Unlock()
	if n > 0 {
		r.write.Do(func() {
			close(r.wrote)
		})
	}
	return n, err
}

// body returns what the handler has written so far.
func (r *flushRecorder) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Body.String()
}

// waitForBody waits until the body contains substr at least n times.
func waitForBody(t *testing.T, r *flushRecorder, substr string, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for strings.Count(r.body(), substr) < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d x %q in stream; got %q", n, substr, r.body())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// openEvents starts an /events stream for the session and returns its
// recorder, a cancel func, and a channel that closes when the handler
// returns. It waits for the stream to start.
func openEvents(t *testing.T, s *server, realm, sessionID string, w http.ResponseWriter, rec *flushRecorder) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/v1/"+realm+"/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+sessionID)
	done := make(chan struct{})
	go func() {
		s.handle(w, req)
		close(done)
	}()
	select {
	case <-rec.flushed:
	case <-time.After(time.Second):
		t.Fatal("events stream did not start")
	}
	return cancel, done
}

// registerRealm registers realm and returns its session ID.
func registerRealm(t *testing.T, s *server, realm string) string {
	t.Helper()
	resp := doRequest(t, s, http.MethodPost, "/v1/"+realm, testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("register status = %d, body = %s", resp.Code, resp.Body.String())
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}
	return rb.SessionID
}

func connectBody(nonce string) map[string]any {
	return map[string]any{
		"addresses": []string{"198.51.100.20:4433"},
		"nonce":     nonce,
		"obfs":      testObfs,
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
