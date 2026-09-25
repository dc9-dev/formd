package netutil

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "127.0.0.1,::1")
	cases := []struct {
		name, remote, xri, xff, want string
	}{
		{"direct, headers ignored", "203.0.113.9:1234", "1.1.1.1", "2.2.2.2", "203.0.113.9"},
		{"trusted proxy, X-Real-IP", "127.0.0.1:5555", "198.51.100.7", "", "198.51.100.7"},
		{"trusted proxy, XFF rightmost untrusted", "127.0.0.1:5555", "", "6.6.6.6, 198.51.100.8", "198.51.100.8"},
		{"trusted proxy, garbage X-Real-IP falls back to XFF", "127.0.0.1:5555", "nope", "198.51.100.8", "198.51.100.8"},
		{"trusted proxy, no headers", "127.0.0.1:5555", "", "", "127.0.0.1"},
		{"ipv4-mapped peer", "[::ffff:203.0.113.9]:1", "", "", "203.0.113.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			if c.xri != "" {
				r.Header.Set("X-Real-IP", c.xri)
			}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := ClientIP(r, trusted).String(); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

func TestAllowIPs(t *testing.T) {
	h := AllowIPs(mustPrefixes(t, "127.0.0.1,10.0.0.0/8"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for remote, want := range map[string]int{
		"127.0.0.1:1":   200,
		"10.1.2.3:1":    200,
		"192.168.1.1:1": 403,
		"garbage":       403,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "127.0.0.1") // must not help
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: got %d want %d", remote, w.Code, want)
		}
	}
}

func TestCheckListenAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8025": true,
		"[::1]:8025":     true,
		"0.0.0.0:8025":   false,
		":8025":          false,
		"localhost:8025": false,
	} {
		if _, err := CheckListenAddr(addr); (err == nil) != ok {
			t.Errorf("%s: err=%v", addr, err)
		}
	}
}
