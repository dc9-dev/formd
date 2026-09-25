// Package server is the public form endpoint that sits behind the reverse proxy.
package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dc9-dev/formd/internal/antispam"
	"github.com/dc9-dev/formd/internal/config"
	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/netutil"
	"github.com/dc9-dev/formd/internal/store"
)

//go:embed formd.js
var clientJS []byte

type Public struct {
	Cfg        *config.Config
	Forms      *forms.Registry
	Store      *store.Store
	Challenger *antispam.Challenger
	Limiter    *antispam.Limiter
	Wake       func()
	Log        *slog.Logger
	Now        func() time.Time
}

// Handler returns the full public handler, including the IP allowlist.
func (p *Public) Handler() http.Handler {
	if p.Now == nil {
		p.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /f/{id}", p.submit)
	mux.HandleFunc("OPTIONS /f/{id}", p.preflight)
	mux.HandleFunc("GET /f/{id}/challenge", p.challenge)
	mux.HandleFunc("OPTIONS /f/{id}/challenge", p.preflight)
	mux.HandleFunc("GET /f/formd.js", p.script)
	mux.HandleFunc("GET /healthz", p.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return netutil.AllowIPs(p.Cfg.AllowedIPs, securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		next.ServeHTTP(w, r)
	})
}

func (p *Public) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := p.Store.Ping(ctx); err != nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

func (p *Public) script(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(clientJS)
}

// requestOrigin returns the browser origin: the Origin header, or the origin
// part of Referer as a fallback.
func requestOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return o
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func setCORS(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, POST")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Accept")
	h.Set("Access-Control-Max-Age", "600")
}

func (p *Public) activeForm(r *http.Request) *forms.Form {
	f := p.Forms.Get(r.PathValue("id"))
	if f == nil || !f.Def.Enabled {
		return nil
	}
	return f
}

func (p *Public) preflight(w http.ResponseWriter, r *http.Request) {
	f := p.activeForm(r)
	origin := r.Header.Get("Origin")
	if f == nil || !f.OriginAllowed(origin) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	setCORS(w, origin)
	w.WriteHeader(http.StatusNoContent)
}

func (p *Public) challenge(w http.ResponseWriter, r *http.Request) {
	f := p.activeForm(r)
	if f == nil || !f.Def.Challenge {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false})
		return
	}
	// Same-origin GETs may omit Origin; if present it must be allowed.
	if origin := r.Header.Get("Origin"); origin != "" {
		if !f.OriginAllowed(origin) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false})
			return
		}
		setCORS(w, origin)
	}
	ip := netutil.ClientIP(r, p.Cfg.TrustedProxies).String()
	now := p.Now()
	if !p.Limiter.Allow("c|"+ip, p.Cfg.ChallengeRate.N, p.Cfg.ChallengeRate.Window, now) {
		p.reject(r, f.Def.ID, ip, "challenge_rate_limit")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":       p.Challenger.Issue(f.Def.ID, f.Def.PowBits, now),
		"bits":        f.Def.PowBits,
		"min_seconds": f.Def.MinSeconds,
	})
}

func (p *Public) reject(r *http.Request, formID, ip, reason string) {
	// Stable key=value format; suitable for fail2ban.
	p.Log.Warn("formd rejected", "reason", reason, "ip", ip, "form", formID, "ua", forms.CleanHeader(r.UserAgent(), 200))
}

func (p *Public) submit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := p.Now()
	ip := netutil.ClientIP(r, p.Cfg.TrustedProxies).String()
	wantJSON := strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")

	f := p.activeForm(r)
	if f == nil {
		p.reject(r, r.PathValue("id"), ip, "unknown_form")
		p.fail(w, r, nil, wantJSON, http.StatusNotFound, map[string]string{"_form": "nie znaleziono formularza"})
		return
	}
	id := f.Def.ID

	origin := requestOrigin(r)
	if !f.OriginAllowed(origin) {
		p.reject(r, id, ip, "origin")
		p.fail(w, r, nil, wantJSON, http.StatusForbidden, map[string]string{"_form": "niedozwolone źródło"})
		return
	}
	if o := r.Header.Get("Origin"); o != "" {
		setCORS(w, o)
	}

	if !p.Limiter.Allow("g|"+ip, p.Cfg.GlobalRatePerIP.N, p.Cfg.GlobalRatePerIP.Window, now) ||
		!p.Limiter.Allow("f|"+id+"|"+ip, f.Def.RatePerIP, time.Duration(f.Def.RateWindowMin)*time.Minute, now) {
		p.reject(r, id, ip, "rate_limit")
		w.Header().Set("Retry-After", "600")
		p.fail(w, r, f, wantJSON, http.StatusTooManyRequests, map[string]string{"_form": "zbyt wiele zgłoszeń, spróbuj później"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, p.Cfg.MaxBody)
	vals, err := forms.ParseRequest(r, p.Cfg.MaxBody)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, forms.ErrTooLarge):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, forms.ErrUnsupported):
			status = http.StatusUnsupportedMediaType
		}
		p.reject(r, id, ip, "parse")
		p.fail(w, r, f, wantJSON, status, map[string]string{"_form": "nieprawidłowe żądanie"})
		return
	}

	res := f.Validate(vals)
	if !res.OK() {
		p.fail(w, r, f, wantJSON, http.StatusBadRequest, res.Errors)
		return
	}

	var nonce string
	var nonceExp time.Time
	if f.Def.Challenge {
		v, err := p.Challenger.Verify(res.Challenge, res.Pow, id, f.Def.PowBits, time.Duration(f.Def.MinSeconds)*time.Second, now)
		if err != nil {
			p.reject(r, id, ip, "challenge: "+err.Error())
			msg := "weryfikacja nie powiodła się, odśwież stronę i spróbuj ponownie"
			if errors.Is(err, antispam.ErrChallengeTooNew) {
				msg = "formularz wysłano zbyt szybko, spróbuj ponownie za chwilę"
			}
			p.fail(w, r, f, wantJSON, http.StatusBadRequest, map[string]string{"_form": msg})
			return
		}
		nonce, nonceExp = v.Nonce, v.IssuedAt.Add(antispam.MaxChallengeAge+time.Hour)
	}

	// From here on, spam and duplicates are answered with a fake success so
	// bots get no signal about which check caught them.
	fakeOK := func(reason string) {
		if nonce != "" {
			if err := p.Store.SpendNonce(ctx, nonce, nonceExp); errors.Is(err, store.ErrReplay) {
				reason += " (replay)"
			}
		}
		p.reject(r, id, ip, reason)
		p.succeed(w, r, f, wantJSON, store.NewID())
	}
	if res.Spam != "" {
		fakeOK("spam: " + res.Spam)
		return
	}

	if f.Def.HourlyCap > 0 {
		n, err := p.Store.CountSubmissionsSince(ctx, id, now.Add(-time.Hour))
		if err != nil {
			p.internal(w, r, f, wantJSON, err)
			return
		}
		if n >= f.Def.HourlyCap {
			p.reject(r, id, ip, "form_hourly_cap")
			p.fail(w, r, f, wantJSON, http.StatusTooManyRequests, map[string]string{"_form": "formularz jest chwilowo przeciążony, spróbuj później"})
			return
		}
	}

	hash := forms.ContentHash(id, res.Values)
	if f.Def.DedupeHours > 0 {
		dup, err := p.Store.DuplicateExists(ctx, id, hash, now.Add(-time.Duration(f.Def.DedupeHours)*time.Hour))
		if err != nil {
			p.internal(w, r, f, wantJSON, err)
			return
		}
		if dup {
			fakeOK("duplicate")
			return
		}
	}

	mails, err := p.buildMails(ctx, f, res.Values, now)
	if err != nil {
		p.internal(w, r, f, wantJSON, err)
		return
	}
	sub := store.Submission{
		ID: store.NewID(), FormID: id, Data: res.Values, ContentHash: hash,
		IP: ip, UserAgent: forms.CleanHeader(r.UserAgent(), 300), CreatedAt: now,
	}
	if err := p.Store.SaveSubmission(ctx, sub, mails, nonce, nonceExp); err != nil {
		if errors.Is(err, store.ErrReplay) {
			p.reject(r, id, ip, "challenge replay")
			p.fail(w, r, f, wantJSON, http.StatusBadRequest, map[string]string{"_form": "weryfikacja nie powiodła się, odśwież stronę i spróbuj ponownie"})
			return
		}
		p.internal(w, r, f, wantJSON, err)
		return
	}
	p.Log.Info("submission accepted", "form", id, "id", sub.ID, "ip", ip, "mails", len(mails))
	if p.Wake != nil {
		p.Wake()
	}
	p.succeed(w, r, f, wantJSON, sub.ID)
}

func (p *Public) buildMails(ctx context.Context, f *forms.Form, values map[string]string, now time.Time) ([]store.OutMail, error) {
	var out []store.OutMail
	if len(f.Def.Notify) > 0 {
		n, err := f.RenderNotify(values)
		if err != nil {
			return nil, err
		}
		replyTo := ""
		if f.Def.ReplyToField != "" {
			replyTo = values[f.Def.ReplyToField] // validated as a bare address
		}
		for _, to := range f.Def.Notify {
			out = append(out, store.OutMail{Kind: "notify", To: to, ReplyTo: replyTo, Subject: n.Subject, Text: n.Text})
		}
	}
	if f.Def.ConfirmEnabled {
		to := values[f.Def.ConfirmToField]
		if to != "" {
			sent, err := p.Store.CountMailsTo(ctx, "confirm", to, now.Add(-24*time.Hour))
			if err != nil {
				return nil, err
			}
			if sent >= f.Def.ConfirmPerRecipientDay {
				p.Log.Warn("formd rejected", "reason", "confirm_recipient_limit", "form", f.Def.ID)
			} else {
				c, err := f.RenderConfirm(values)
				if err != nil {
					return nil, err
				}
				out = append(out, store.OutMail{Kind: "confirm", To: to, Subject: c.Subject, Text: c.Text, HTML: c.HTML})
			}
		}
	}
	return out, nil
}

func (p *Public) internal(w http.ResponseWriter, r *http.Request, f *forms.Form, wantJSON bool, err error) {
	p.Log.Error("submission failed", "err", err)
	p.fail(w, r, f, wantJSON, http.StatusInternalServerError, map[string]string{"_form": "błąd serwera, spróbuj później"})
}

func (p *Public) succeed(w http.ResponseWriter, r *http.Request, f *forms.Form, wantJSON bool, id string) {
	if wantJSON {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
		return
	}
	if f.Def.RedirectSuccess != "" {
		http.Redirect(w, r, f.Def.RedirectSuccess, http.StatusSeeOther)
		return
	}
	renderPage(w, http.StatusOK, "Dziękujemy", "Wiadomość została wysłana.", nil)
}

func (p *Public) fail(w http.ResponseWriter, r *http.Request, f *forms.Form, wantJSON bool, status int, errs map[string]string) {
	if wantJSON {
		writeJSON(w, status, map[string]any{"ok": false, "errors": errs})
		return
	}
	if f != nil && f.Def.RedirectError != "" {
		u, _ := url.Parse(f.Def.RedirectError)
		q := u.Query()
		q.Set("status", strconv.Itoa(status))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	var list []string
	for k, v := range errs {
		if k == "_form" {
			list = append(list, v)
			continue
		}
		label := k
		if f != nil && f.Field(k) != nil {
			label = f.Field(k).Label
		}
		list = append(list, label+": "+v)
	}
	renderPage(w, status, "Nie udało się wysłać formularza", "Wróć do formularza i popraw dane.", list)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:10vh auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}li{color:#a00}</style>
</head><body><h1>{{.Title}}</h1><p>{{.Msg}}</p>{{if .Errors}}<ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}</body></html>`))

func renderPage(w http.ResponseWriter, status int, title, msg string, errs []string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	pageTmpl.Execute(w, map[string]any{"Title": title, "Msg": msg, "Errors": errs})
}
