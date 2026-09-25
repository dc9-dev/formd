// Package netutil holds IP allowlist and client-IP helpers shared by the
// public and admin listeners.
package netutil

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ParsePrefixes parses a comma separated list of IPs and CIDRs.
// A bare IP becomes a single-host prefix.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q: %w", part, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Contains reports whether a is inside any of the prefixes.
func Contains(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// RemoteAddr returns the peer address of the TCP connection.
func RemoteAddr(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// ClientIP returns the end-user IP. Forwarding headers are honoured only when
// the direct peer is a trusted proxy; otherwise they are ignored entirely, so a
// client cannot spoof its address to dodge rate limits.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer, ok := RemoteAddr(r)
	if !ok {
		return netip.Addr{}
	}
	if !Contains(trusted, peer) {
		return peer
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap()
		}
	}
	// Walk X-Forwarded-For from the right, skipping our own proxies: the first
	// untrusted hop is the address the outermost trusted proxy actually saw.
	xff := r.Header.Values("X-Forwarded-For")
	hops := strings.Split(strings.Join(xff, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !Contains(trusted, a) {
			return a
		}
	}
	return peer
}

// AllowIPs rejects any connection whose peer address is outside the list.
// It runs before routing so nothing else is reachable from other hosts.
func AllowIPs(allowed []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := RemoteAddr(r)
		if !ok || !Contains(allowed, peer) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CheckListenAddr requires IP:port bound to a specific, non-wildcard address.
func CheckListenAddr(addr string) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("listen address %q must be IP:port (hostnames and wildcards are not allowed): %w", addr, err)
	}
	if ap.Addr().IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("listen address %q binds to all interfaces; use a specific IP such as 127.0.0.1", addr)
	}
	return ap.Addr(), nil
}
