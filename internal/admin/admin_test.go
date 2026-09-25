package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dc9-dev/formd/internal/config"
	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/store"
)

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func setup(t *testing.T) (*client, *store.Store, *forms.Registry) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := HashPassword("correct horse battery")
	if err := st.CreateUser(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AdminAllowedIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		AdminHosts:      []string{"localhost", "127.0.0.1"},
		SessionTTL:      time.Hour, SessionIdle: time.Hour,
	}
	reg := forms.NewRegistry()
	a, err := New(cfg, st, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, h: a.Handler()}, st, reg
}

func (c *client) req(method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, "http://localhost:8026"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, "http://localhost:8026"+path, nil)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func (c *client) login(pw string) *httptest.ResponseRecorder {
	w := c.req("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}}, nil)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
				c.t.Fatalf("insecure cookie flags: %+v", ck)
			}
			c.cookie = ck
		}
	}
	return w
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (c *client) csrf() string {
	w := c.req("GET", "/", nil, nil)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		c.t.Fatalf("no csrf token on page: %d", w.Code)
	}
	return m[1]
}

func TestAccessControl(t *testing.T) {
	c, _, _ := setup(t)

	// Unauthenticated → login.
	if w := c.req("GET", "/", nil, nil); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("unauth: %d", w.Code)
	}
	// DNS rebinding: foreign Host header.
	r := httptest.NewRequest("GET", "http://attacker.example:8026/login", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("foreign host: %d", w.Code)
	}
	// Foreign peer.
	r = httptest.NewRequest("GET", "http://localhost/login", nil)
	r.RemoteAddr = "10.0.0.5:1"
	w = httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("foreign peer: %d", w.Code)
	}
	// Security headers.
	w = c.req("GET", "/login", nil, nil)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %v", w.Header())
	}
}

func TestLoginThrottleAndCSRF(t *testing.T) {
	c, st, reg := setup(t)
	if w := c.login("wrong password!"); w.Code != 401 || c.cookie != nil {
		t.Fatalf("bad password: %d", w.Code)
	}
	if w := c.login("correct horse battery"); w.Code != 303 || c.cookie == nil {
		t.Fatalf("login: %d", w.Code)
	}
	token := c.csrf()

	create := url.Values{"id": {"kontakt"}, "title": {"Kontakt"}, "origin": {"https://example.com"}}
	// Missing CSRF token.
	if w := c.req("POST", "/forms/new", create, nil); w.Code != 403 {
		t.Fatalf("no csrf: %d", w.Code)
	}
	// Cross-site request with a valid token is still refused.
	create.Set("csrf", token)
	if w := c.req("POST", "/forms/new", create, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != 403 {
		t.Fatalf("cross-site: %d", w.Code)
	}
	if w := c.req("POST", "/forms/new", create, map[string]string{"Origin": "https://evil.com"}); w.Code != 403 {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	if w := c.req("POST", "/forms/new", create, map[string]string{"Origin": "http://localhost:8026", "Sec-Fetch-Site": "same-origin"}); w.Code != 303 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	d, err := st.GetForm(context.Background(), "kontakt")
	if err != nil || d.Enabled {
		t.Fatalf("new form should exist and be disabled: %v %+v", err, d)
	}

	// Edit: enable + stored XSS attempt in the title is escaped on render.
	edit := url.Values{
		"csrf": {token}, "title": {`<script>alert(1)</script>`}, "enabled": {"1"}, "allowed_origins": {"https://example.com"},
		"challenge": {"1"}, "pow_bits": {"12"}, "min_seconds": {"2"}, "rate_per_ip": {"5"}, "rate_window_min": {"10"},
		"field_name": {"email", ""}, "field_label": {"E-mail", ""}, "field_type": {"email", "text"}, "field_required": {"1", "0"}, "field_max": {"", ""},
	}
	if w := c.req("POST", "/forms/kontakt", edit, nil); w.Code != 303 {
		t.Fatalf("edit: %d %s", w.Code, w.Body)
	}
	if f := reg.Get("kontakt"); f == nil || !f.Def.Enabled || f.Def.PowBits != 12 {
		t.Fatalf("registry not reloaded: %+v", f)
	}
	if body := c.req("GET", "/", nil, nil).Body.String(); strings.Contains(body, "<script>alert(1)") {
		t.Fatal("title not escaped")
	}

	// Invalid edit is refused and nothing changes.
	edit.Set("allowed_origins", "javascript:alert(1)")
	if w := c.req("POST", "/forms/kontakt", edit, nil); w.Code != 400 {
		t.Fatalf("invalid edit: %d", w.Code)
	}

	// Throttle: 5 failures per username per 15 min.
	c.cookie = nil
	for i := 0; i < 5; i++ {
		c.login("nope nope nope")
	}
	if w := c.login("correct horse battery"); w.Code != 401 || !strings.Contains(w.Body.String(), "Zbyt wiele") {
		t.Fatalf("throttle not applied: %d", w.Code)
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("secret password 1")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "secret password 1") || VerifyPassword(h, "secret password 2") || VerifyPassword("garbage", "x") {
		t.Fatal("verify mismatch")
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=HYPERLINK(1)": "'=HYPERLINK(1)", "+1": "'+1", "@x": "'@x", "ok": "ok", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
}
