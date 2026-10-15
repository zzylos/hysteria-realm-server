package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	maxAddresses   = 8
	nonceHexLength = 32 // 16 bytes
	obfsHexLength  = 64 // 32 bytes
)

const (
	errBadRequest      = "bad_request"
	errInvalidToken    = "invalid_token"
	errRealmTaken      = "realm_taken"
	errRealmLimit      = "realm_limit_reached"
	errIPLimit         = "ip_limit_reached"
	errRealmNotFound   = "realm_not_found"
	errAttemptNotFound = "attempt_not_found"
	errAttemptExists   = "attempt_exists"
	errRateLimited     = "rate_limited"
	errNotFound        = "not_found"
	errInternal        = "internal_error"
)

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP returns the IP of the client that sent r.
//
// With a proxy header configured, the client is the rightmost entry of that
// header that is not a trusted proxy. Proxies append the address they saw,
// so entries further left were written by the client and can be anything.
// When trusted proxies are configured, the header is only read on requests
// that come from one of them.
func clientIP(r *http.Request, header string, trusted []netip.Prefix) string {
	remote, ok := parseIPOrHostPort(r.RemoteAddr)
	if !ok {
		host := r.RemoteAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return host
	}
	if header == "" || (len(trusted) > 0 && !inPrefixes(trusted, remote)) {
		return remote.String()
	}
	var entries []string
	for _, v := range r.Header.Values(header) {
		entries = append(entries, strings.Split(v, ",")...)
	}
	client := remote
	for i := len(entries) - 1; i >= 0; i-- {
		addr, ok := parseIPOrHostPort(strings.TrimSpace(entries[i]))
		if !ok {
			break
		}
		client = addr
		if len(trusted) == 0 || !inPrefixes(trusted, addr) {
			break
		}
	}
	return client.String()
}

// parseIPOrHostPort parses "ip" or "ip:port" (with brackets for IPv6).
func parseIPOrHostPort(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

func inPrefixes(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses a comma-separated list of IPs and CIDRs.
func parseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", part, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", part, err)
		}
		addr = addr.Unmap().WithZone("")
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func validateAddresses(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("at least one address required")
	}
	if len(addrs) > maxAddresses {
		return fmt.Errorf("too many addresses (max %d)", maxAddresses)
	}
	for _, a := range addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil || !ap.IsValid() {
			return fmt.Errorf("invalid address: %s", a)
		}
		if !usablePeerAddr(ap) {
			return fmt.Errorf("address cannot be used by a remote peer: %s", a)
		}
	}
	return nil
}

var ipv4Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// usablePeerAddr reports whether a peer on another network could reach
// addr. Port 0, unspecified, loopback, link-local, multicast and broadcast
// addresses never qualify. Accepting them would let anyone with the realm
// token make a realm server send punch packets to itself, to its link-local
// neighbors, or to multicast groups. Private ranges stay allowed, because
// realms can run on private networks with a private STUN server.
func usablePeerAddr(ap netip.AddrPort) bool {
	if ap.Port() == 0 || ap.Addr().Zone() != "" {
		return false
	}
	addr := ap.Addr().Unmap()
	return !addr.IsUnspecified() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsMulticast() &&
		addr != ipv4Broadcast
}

func validateHexField(name, value string, length int) error {
	if len(value) != length {
		return fmt.Errorf("%s must be %d hex characters", name, length)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be valid hex", name)
	}
	return nil
}
