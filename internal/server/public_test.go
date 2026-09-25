package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dc9-dev/formd/internal/antispam"
	"github.com/dc9-dev/formd/internal/config"
	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/store"
)

type env struct {
	t     *testing.T
	pub   *Public
	h     http.Handler
	store *store.Store
	now   time.Time
}

func newEnv(t *testing.T, mut func(d *forms.Definition)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	d := forms.NewDefinition("contact")
	d.Enabled = true
	d.AllowedOrigins = []string{"https://example.com"}
	d.Notify = []string{"owner@example.com"}
	d.PowBits = 8
	d.ConfirmEnabled = true
	if mut != nil {
		mut(&d)
	}
	f, err := forms.Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateForm(context.Background(), f.Def); err != nil {
		t.Fatal(err)
	}
	reg := forms.NewRegistry()
	reg.Load([]forms.Definition{f.Def})

	chal, _ := antispam.NewChallenger(bytes.Repeat([]byte{1}, 32))
	cfg := &config.Config{
		AllowedIPs:      mustP("127.0.0.1"),
		TrustedProxies:  mustP("127.0.0.1"),
		MaxBody:         64 << 10,
		GlobalRatePerIP: config.Rate{N: 100, Window: time.Hour},
		ChallengeRate:   config.Rate{N: 100, Window: time.Hour},
	}
	e := &env{t: t, store: st, now: time.Unix(1_800_000_000, 0)}
	e.pub = &Public{
		Cfg: cfg, Forms: reg, Store: st, Challenger: chal,
		Limiter: antispam.NewLimiter(1000), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return e.now },
	}
	e.h = e.pub.Handler()
	return e
}

func mustP(s string) []netip.Prefix {
	p := []netip.Prefix{}
	for _, part := range strings.Split(s, ",") {
		a := netip.MustParseAddr(part)
		p = append(p, netip.PrefixFrom(a, a.BitLen()))
	}
	return p
}

func (e *env) do(method, path string, body url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(body.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Real-IP", "198.51.100.1")
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// token fetches a challenge and solves it, then advances the clock past min_seconds.
func (e *env) token() (string, string) {
	w := e.do("GET", "/f/contact/challenge", nil, nil)
	if w.Code != 200 {
		e.t.Fatalf("challenge: %d %s", w.Code, w.Body)
	}
	var c struct {
		Token string `json:"token"`
		Bits  int    `json:"bits"`
	}
	json.Unmarshal(w.Body.Bytes(), &c)
	for n := 0; ; n++ {
		if antispam.CheckPow(c.Token, strconv.Itoa(n), c.Bits) {
			e.now = e.now.Add(5 * time.Second)
			return c.Token, strconv.Itoa(n)
		}
	}
}

func valid(tok, pow string) url.Values {
	return url.Values{"name": {"Jan"}, "email": {"jan@example.com"}, "message": {"Dzień dobry"}, "_challenge": {tok}, "_pow": {pow}}
}

func (e *env) outboxCount() int {
	items, err := e.store.RecentOutbox(context.Background(), "", 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(items)
}

func TestSubmitHappyPathAndReplay(t *testing.T) {
	e := newEnv(t, nil)
	tok, pow := e.token()
	w := e.do("POST", "/f/contact", valid(tok, pow), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if n := e.outboxCount(); n != 2 {
		t.Fatalf("want notify+confirm, got %d mails", n)
	}
	subs, _ := e.store.ListSubmissions(context.Background(), "contact", time.Unix(0, 0), 10, 0)
	if len(subs) != 1 || subs[0].IP != "198.51.100.1" {
		t.Fatalf("submission not stored correctly: %+v", subs)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("CORS origin %q", got)
	}

	// Same token again (different content so dedupe does not mask it).
	v := valid(tok, pow)
	v.Set("message", "inna treść")
	if w := e.do("POST", "/f/contact", v, nil); w.Code != 400 {
		t.Fatalf("replay accepted: %d %s", w.Code, w.Body)
	}
}

func TestSubmitRejections(t *testing.T) {
	e := newEnv(t, nil)

	if w := e.do("POST", "/f/contact", valid("", ""), nil); w.Code != 400 {
		t.Errorf("no challenge: %d", w.Code)
	}
	tok, pow := e.token()
	if w := e.do("POST", "/f/contact", valid(tok, pow), map[string]string{"Origin": "https://evil.com"}); w.Code != 403 {
		t.Errorf("foreign origin: %d", w.Code)
	}
	if w := e.do("POST", "/f/contact", valid(tok, pow), map[string]string{"Origin": ""}); w.Code != 403 {
		t.Errorf("no origin: %d", w.Code)
	}
	if w := e.do("POST", "/f/nope", valid(tok, pow), nil); w.Code != 404 {
		t.Errorf("unknown form: %d", w.Code)
	}
	if w := e.do("POST", "/f/contact", valid(tok, "1"), nil); w.Code != 400 {
		t.Errorf("wrong pow: %d", w.Code)
	}
	big := valid(tok, pow)
	big.Set("message", strings.Repeat("a", 70<<10))
	if w := e.do("POST", "/f/contact", big, nil); w.Code != 413 {
		t.Errorf("oversized: %d", w.Code)
	}

	// Too fast: fresh token, clock not advanced.
	w := e.do("GET", "/f/contact/challenge", nil, nil)
	var c struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &c)
	if w := e.do("POST", "/f/contact", valid(c.Token, "0"), nil); w.Code != 400 || !strings.Contains(w.Body.String(), "szybko") {
		t.Errorf("too fast: %d %s", w.Code, w.Body)
	}

	// Connection from a non-allowlisted IP never reaches the handler.
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.RemoteAddr = "203.0.113.5:1"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Errorf("foreign peer: %d", rec.Code)
	}
	if n := e.outboxCount(); n != 0 {
		t.Errorf("rejected requests queued %d mails", n)
	}
}

func TestSpamIsSilentlyDropped(t *testing.T) {
	e := newEnv(t, nil)
	tok, pow := e.token()
	v := valid(tok, pow)
	v.Set("website", "http://spam")
	w := e.do("POST", "/f/contact", v, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("honeypot should look like success, got %d", w.Code)
	}
	if n := e.outboxCount(); n != 0 {
		t.Fatalf("spam queued %d mails", n)
	}
	// Token spent even though the submission was dropped.
	if w := e.do("POST", "/f/contact", valid(tok, pow), nil); w.Code != 400 {
		t.Fatalf("token reusable after spam: %d", w.Code)
	}
}

func TestDuplicateDropped(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 2; i++ {
		tok, pow := e.token()
		if w := e.do("POST", "/f/contact", valid(tok, pow), nil); w.Code != 200 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	subs, _ := e.store.ListSubmissions(context.Background(), "contact", time.Unix(0, 0), 10, 0)
	if len(subs) != 1 {
		t.Fatalf("duplicate stored: %d", len(subs))
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, func(d *forms.Definition) { d.RatePerIP = 2; d.RateWindowMin = 10; d.DedupeHours = 0 })
	codes := []int{}
	for i := 0; i < 3; i++ {
		tok, pow := e.token()
		v := valid(tok, pow)
		v.Set("message", "m"+strconv.Itoa(i))
		codes = append(codes, e.do("POST", "/f/contact", v, nil).Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("per-IP limit: %v", codes)
	}
	// Spoofed X-Real-IP from a non-trusted peer is ignored → still limited by peer.
	// A different real client (via trusted proxy) is not affected.
	tok, pow := e.token()
	if w := e.do("POST", "/f/contact", valid(tok, pow), map[string]string{"X-Real-IP": "198.51.100.2"}); w.Code != 200 {
		t.Fatalf("other client limited: %d", w.Code)
	}
}

func TestHourlyCapAndConfirmLimit(t *testing.T) {
	e := newEnv(t, func(d *forms.Definition) {
		d.HourlyCap = 3
		d.RatePerIP = 0
		d.DedupeHours = 0
		d.ConfirmPerRecipientDay = 1
	})
	var codes []int
	for i := 0; i < 4; i++ {
		tok, pow := e.token()
		v := valid(tok, pow)
		v.Set("message", "m"+strconv.Itoa(i))
		codes = append(codes, e.do("POST", "/f/contact", v, nil).Code)
	}
	if codes[3] != 429 {
		t.Fatalf("hourly cap not enforced: %v", codes)
	}
	items, _ := e.store.RecentOutbox(context.Background(), "", 100)
	confirms := 0
	for _, it := range items {
		if it.Kind == "confirm" {
			confirms++
		}
	}
	if confirms != 1 {
		t.Fatalf("confirmations to one address: %d, want 1", confirms)
	}
}

func TestNoJSFallbackRedirect(t *testing.T) {
	e := newEnv(t, func(d *forms.Definition) {
		d.RedirectSuccess = "https://example.com/ok.html"
		d.RedirectError = "https://example.com/err.html"
	})
	tok, pow := e.token()
	w := e.do("POST", "/f/contact", valid(tok, pow), map[string]string{"Accept": "text/html"})
	if w.Code != 303 || w.Header().Get("Location") != "https://example.com/ok.html" {
		t.Fatalf("success redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = e.do("POST", "/f/contact", valid("", ""), map[string]string{"Accept": "text/html"})
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "https://example.com/err.html?status=400") {
		t.Fatalf("error redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
}
