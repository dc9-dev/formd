// Package admin is the configuration panel. It runs on its own listener
// (never behind the public proxy), and every request passes: IP allowlist →
// Host allowlist (DNS rebinding) → strict security headers → same-origin
// check for state-changing requests → session auth → per-session CSRF token.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dc9-dev/formd/internal/antispam"
	"github.com/dc9-dev/formd/internal/config"
	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/netutil"
	"github.com/dc9-dev/formd/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	cookieName   = "formd_admin"
	maxAdminBody = 256 << 10
)

type Admin struct {
	Cfg   *config.Config
	Store *store.Store
	Forms *forms.Registry
	Log   *slog.Logger

	limiter *antispam.Limiter
	pages   map[string]*template.Template
}

func New(cfg *config.Config, st *store.Store, reg *forms.Registry, log *slog.Logger) (*Admin, error) {
	a := &Admin{Cfg: cfg, Store: st, Forms: reg, Log: log, limiter: antispam.NewLimiter(10_000), pages: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"time":  func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"lines": func(v []string) string { return strings.Join(v, "\n") },
		"add":   func(a, b int) int { return a + b },
	}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", n)
		if err != nil {
			return nil, err
		}
		a.pages[base] = t
	}
	return a, nil
}

type handler func(w http.ResponseWriter, r *http.Request, s *store.Session)

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.loginSubmit)
	mux.Handle("POST /logout", a.auth(a.logout))

	mux.Handle("GET /{$}", a.auth(a.dashboard))
	mux.Handle("GET /forms/new", a.auth(a.newFormPage))
	mux.Handle("POST /forms/new", a.auth(a.newFormSubmit))
	mux.Handle("GET /forms/{id}", a.auth(a.editPage))
	mux.Handle("POST /forms/{id}", a.auth(a.editSubmit))
	mux.Handle("GET /forms/{id}/delete", a.auth(a.deletePage))
	mux.Handle("POST /forms/{id}/delete", a.auth(a.deleteSubmit))
	mux.Handle("GET /forms/{id}/snippet", a.auth(a.snippet))
	mux.Handle("GET /forms/{id}/submissions", a.auth(a.submissions))
	mux.Handle("POST /forms/{id}/submissions/{sid}/delete", a.auth(a.deleteSubmission))
	mux.Handle("GET /forms/{id}/export.csv", a.auth(a.exportCSV))
	mux.Handle("GET /outbox", a.auth(a.outbox))
	mux.Handle("POST /outbox/{oid}/retry", a.auth(a.retry))
	mux.Handle("GET /audit", a.auth(a.auditPage))
	mux.Handle("GET /account", a.auth(a.accountPage))
	mux.Handle("POST /account", a.auth(a.accountSubmit))

	var h http.Handler = mux
	h = a.sameOrigin(h)
	h = headers(h)
	h = a.hostCheck(h)
	h = netutil.AllowIPs(a.Cfg.AdminAllowedIPs, h)
	return h
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
		next.ServeHTTP(w, r)
	})
}

// hostCheck defeats DNS rebinding: a hostile page resolving its own name to
// 127.0.0.1 still sends its own Host header, which is refused here.
func (a *Admin) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(strings.ToLower(host), "[]")
		for _, ok := range a.Cfg.AdminHosts {
			if host == strings.Trim(ok, "[]") {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden host", http.StatusForbidden)
	})
}

// sameOrigin rejects cross-site state-changing requests (defence in depth on
// top of SameSite=Strict cookies and CSRF tokens).
func (a *Admin) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) auth(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" || len(c.Value) > 128 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s, err := a.Store.GetSession(r.Context(), c.Value, a.Cfg.SessionIdle, time.Now())
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				a.Log.Error("session lookup", "err", err)
			}
			a.clearCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.CSRF)) != 1 {
				a.audit(r, s.Username, "csrf_failed", r.URL.Path)
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		h(w, r, &s)
	})
}

func (a *Admin) setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: a.Cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (a *Admin) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.Cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *Admin) clientIP(r *http.Request) string {
	ip, _ := netutil.RemoteAddr(r)
	return ip.String()
}

func (a *Admin) audit(r *http.Request, user, action, detail string) {
	if err := a.Store.Audit(context.WithoutCancel(r.Context()), user, a.clientIP(r), action, forms.CleanHeader(detail, 500)); err != nil {
		a.Log.Error("audit write failed", "err", err)
	}
	a.Log.Info("admin audit", "user", user, "ip", a.clientIP(r), "action", action, "detail", detail)
}

// view is the data passed to every template.
type view struct {
	Title   string
	Session *store.Session
	Flash   string
	Error   string
	Errors  []string
	Data    any
}

var flashes = map[string]string{
	"saved":    "Zapisano zmiany.",
	"created":  "Utworzono formularz. Uzupełnij konfigurację i włącz go.",
	"deleted":  "Usunięto.",
	"requeued": "Wiadomość wróciła do kolejki.",
	"password": "Hasło zmienione. Zaloguj się ponownie.",
}

func (a *Admin) render(w http.ResponseWriter, r *http.Request, status int, page string, v view) {
	t := a.pages[page]
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	if v.Flash == "" {
		v.Flash = flashes[r.URL.Query().Get("ok")]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout.html", v); err != nil {
		a.Log.Error("render", "page", page, "err", err)
	}
}

func (a *Admin) serverError(w http.ResponseWriter, err error) {
	a.Log.Error("admin error", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// reloadForms refreshes the public registry after a change.
func (a *Admin) reloadForms(ctx context.Context) error {
	return ReloadRegistry(ctx, a.Store, a.Forms, a.Log)
}

// ReloadRegistry loads all definitions from the store into the registry.
func ReloadRegistry(ctx context.Context, st *store.Store, reg *forms.Registry, log *slog.Logger) error {
	rows, err := st.ListForms(ctx)
	if err != nil {
		return err
	}
	defs := make([]forms.Definition, len(rows))
	for i, r := range rows {
		defs[i] = r.Def
	}
	for _, err := range reg.Load(defs) {
		log.Error("form not loaded", "err", err)
	}
	return nil
}
