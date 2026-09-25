package admin

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dc9-dev/formd/internal/forms"
	"github.com/dc9-dev/formd/internal/store"
)

// ---- login ----

func (a *Admin) loginPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "login", view{Title: "Logowanie"})
}

func (a *Admin) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.PostForm.Get("username"))
	pass := r.PostForm.Get("password")
	ip := a.clientIP(r)
	now := time.Now()
	fail := func(msg string) {
		a.render(w, r, http.StatusUnauthorized, "login", view{Title: "Logowanie", Error: msg})
	}
	if len(user) > 64 {
		fail("Nieprawidłowy login lub hasło.")
		return
	}
	// Throttle per IP and per username before doing any expensive work.
	if !a.limiter.Allow("ip|"+ip, 10, 15*time.Minute, now) || !a.limiter.Allow("user|"+strings.ToLower(user), 5, 15*time.Minute, now) {
		a.audit(r, user, "login_throttled", "")
		fail("Zbyt wiele prób logowania. Spróbuj za kilkanaście minut.")
		return
	}
	u, err := a.Store.UserByName(r.Context(), user)
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	} else if !errors.Is(err, store.ErrNotFound) {
		a.serverError(w, err)
		return
	}
	if !VerifyPassword(hash, pass) || err != nil {
		a.audit(r, user, "login_failed", "")
		fail("Nieprawidłowy login lub hasło.")
		return
	}
	token := randToken()
	expires := now.Add(a.Cfg.SessionTTL)
	if err := a.Store.CreateSession(r.Context(), token, u.ID, randToken(), ip, forms.CleanHeader(r.UserAgent(), 300), expires); err != nil {
		a.serverError(w, err)
		return
	}
	a.setCookie(w, token, expires)
	a.audit(r, u.Username, "login", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request, s *store.Session) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.Store.DeleteSession(r.Context(), c.Value)
	}
	a.clearCookie(w)
	a.audit(r, s.Username, "logout", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard ----

type dashRow struct {
	Def   forms.Definition
	Count int
	Live  bool
}

func (a *Admin) dashboard(w http.ResponseWriter, r *http.Request, s *store.Session) {
	ctx := r.Context()
	rows, err := a.Store.ListForms(ctx)
	if err != nil {
		a.serverError(w, err)
		return
	}
	counts, err := a.Store.CountSubmissions(ctx)
	if err != nil {
		a.serverError(w, err)
		return
	}
	failed, err := a.Store.RecentOutbox(ctx, "failed", 1000)
	if err != nil {
		a.serverError(w, err)
		return
	}
	var list []dashRow
	for _, fr := range rows {
		f := a.Forms.Get(fr.Def.ID)
		list = append(list, dashRow{Def: fr.Def, Count: counts[fr.Def.ID], Live: f != nil && f.Def.Enabled})
	}
	a.render(w, r, http.StatusOK, "dashboard", view{Title: "Formularze", Session: s, Data: map[string]any{
		"Forms": list, "Failed": len(failed), "Mailer": a.Cfg.Mailer,
	}})
}

// ---- create ----

func (a *Admin) newFormPage(w http.ResponseWriter, r *http.Request, s *store.Session) {
	a.render(w, r, http.StatusOK, "new", view{Title: "Nowy formularz", Session: s, Data: map[string]string{}})
}

func (a *Admin) newFormSubmit(w http.ResponseWriter, r *http.Request, s *store.Session) {
	in := map[string]string{
		"id":     strings.TrimSpace(r.PostForm.Get("id")),
		"title":  strings.TrimSpace(r.PostForm.Get("title")),
		"origin": strings.TrimSpace(r.PostForm.Get("origin")),
	}
	d := forms.NewDefinition(in["id"])
	if in["title"] != "" {
		d.Title = in["title"]
	}
	d.AllowedOrigins = []string{in["origin"]}
	if _, err := forms.Compile(d); err != nil {
		a.render(w, r, http.StatusBadRequest, "new", view{Title: "Nowy formularz", Session: s, Errors: splitErr(err), Data: in})
		return
	}
	f, _ := forms.Compile(d)
	if err := a.Store.CreateForm(r.Context(), f.Def); err != nil {
		if errors.Is(err, store.ErrExists) {
			a.render(w, r, http.StatusConflict, "new", view{Title: "Nowy formularz", Session: s, Errors: []string{"Formularz o tym identyfikatorze już istnieje."}, Data: in})
			return
		}
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "form_create", f.Def.ID)
	a.reloadForms(r.Context())
	http.Redirect(w, r, "/forms/"+url.PathEscape(f.Def.ID)+"?ok=created", http.StatusSeeOther)
}

// ---- edit ----

func (a *Admin) loadDef(w http.ResponseWriter, r *http.Request) (forms.Definition, bool) {
	d, err := a.Store.GetForm(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return d, false
	}
	if err != nil {
		a.serverError(w, err)
		return d, false
	}
	return d, true
}

type editData struct {
	Def   forms.Definition
	Rows  []forms.Field
	Types []string
}

func editView(d forms.Definition) editData {
	rows := append([]forms.Field{}, d.Fields...)
	for i := 0; i < 3; i++ {
		rows = append(rows, forms.Field{Type: forms.TypeText})
	}
	return editData{Def: d, Rows: rows, Types: []string{forms.TypeText, forms.TypeTextarea, forms.TypeEmail}}
}

func (a *Admin) editPage(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	a.render(w, r, http.StatusOK, "edit", view{Title: "Formularz: " + d.Title, Session: s, Data: editView(d)})
}

func (a *Admin) editSubmit(w http.ResponseWriter, r *http.Request, s *store.Session) {
	cur, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	d, perr := parseDefinition(r.PostForm, cur.ID)
	f, err := forms.Compile(d)
	if perr != nil || err != nil {
		errs := append(splitErr(perr), splitErr(err)...)
		a.render(w, r, http.StatusBadRequest, "edit", view{Title: "Formularz: " + cur.Title, Session: s, Errors: errs, Data: editView(d)})
		return
	}
	if err := a.Store.UpdateForm(r.Context(), f.Def); err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "form_update", fmt.Sprintf("%s enabled=%t challenge=%t pow=%d rate=%d/%dm cap=%d", f.Def.ID, f.Def.Enabled, f.Def.Challenge, f.Def.PowBits, f.Def.RatePerIP, f.Def.RateWindowMin, f.Def.HourlyCap))
	if err := a.reloadForms(r.Context()); err != nil {
		a.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/forms/"+url.PathEscape(f.Def.ID)+"?ok=saved", http.StatusSeeOther)
}

// parseDefinition maps the edit form onto a Definition. Structural checks are
// left to forms.Compile; this only reports unparseable numbers.
func parseDefinition(v url.Values, id string) (forms.Definition, error) {
	var errs []string
	num := func(key, label string) int {
		s := strings.TrimSpace(v.Get(key))
		if s == "" {
			return 0
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			errs = append(errs, label+": wymagana liczba całkowita")
		}
		return n
	}
	d := forms.Definition{
		ID:                     id,
		Title:                  v.Get("title"),
		Enabled:                v.Get("enabled") == "1",
		AllowedOrigins:         splitLines(v.Get("allowed_origins")),
		Honeypot:               v.Get("honeypot"),
		Challenge:              v.Get("challenge") == "1",
		PowBits:                num("pow_bits", "trudność PoW"),
		MinSeconds:             num("min_seconds", "minimalny czas"),
		RatePerIP:              num("rate_per_ip", "limit per IP"),
		RateWindowMin:          num("rate_window_min", "okno limitu"),
		HourlyCap:              num("hourly_cap", "limit godzinowy"),
		MaxLinks:               num("max_links", "max linków"),
		BlockedWords:           splitLines(v.Get("blocked_words")),
		DedupeHours:            num("dedupe_hours", "duplikaty"),
		RetentionDays:          num("retention_days", "retencja"),
		Notify:                 splitLines(v.Get("notify")),
		NotifySubject:          v.Get("notify_subject"),
		ReplyToField:           v.Get("reply_to_field"),
		ConfirmEnabled:         v.Get("confirm_enabled") == "1",
		ConfirmToField:         v.Get("confirm_to_field"),
		ConfirmSubject:         v.Get("confirm_subject"),
		ConfirmText:            strings.ReplaceAll(v.Get("confirm_text"), "\r\n", "\n"),
		ConfirmHTML:            strings.ReplaceAll(v.Get("confirm_html"), "\r\n", "\n"),
		ConfirmPerRecipientDay: num("confirm_per_recipient_day", "limit potwierdzeń"),
		RedirectSuccess:        v.Get("redirect_success"),
		RedirectError:          v.Get("redirect_error"),
	}
	if strings.TrimSpace(v.Get("max_links")) == "" {
		d.MaxLinks = -1
	}
	names, labels, types, req, maxes := v["field_name"], v["field_label"], v["field_type"], v["field_required"], v["field_max"]
	if len(names) > 60 {
		errs = append(errs, "zbyt wiele pól")
		names = names[:60]
	}
	at := func(s []string, i int) string {
		if i < len(s) {
			return s[i]
		}
		return ""
	}
	for i, n := range names {
		max, err := strconv.Atoi(strings.TrimSpace(at(maxes, i)))
		if err != nil && strings.TrimSpace(at(maxes, i)) != "" {
			errs = append(errs, "pole "+n+": max długość musi być liczbą")
		}
		d.Fields = append(d.Fields, forms.Field{
			Name: n, Label: at(labels, i), Type: at(types, i), Required: at(req, i) == "1", Max: max,
		})
	}
	if len(errs) > 0 {
		return d, errors.New(strings.Join(errs, "\n"))
	}
	return d, nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func splitErr(err error) []string {
	if err == nil {
		return nil
	}
	return strings.Split(err.Error(), "\n")
}

// ---- delete ----

func (a *Admin) deletePage(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	a.render(w, r, http.StatusOK, "delete", view{Title: "Usuń formularz", Session: s, Data: d})
}

func (a *Admin) deleteSubmit(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != d.ID {
		a.render(w, r, http.StatusBadRequest, "delete", view{Title: "Usuń formularz", Session: s, Data: d, Error: "Wpisz identyfikator formularza, aby potwierdzić."})
		return
	}
	if err := a.Store.DeleteForm(r.Context(), d.ID); err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "form_delete", d.ID)
	a.reloadForms(r.Context())
	http.Redirect(w, r, "/?ok=deleted", http.StatusSeeOther)
}

// ---- snippet ----

func (a *Admin) snippet(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<form action=\"/f/%s\" method=\"post\" data-formd>\n", d.ID)
	for _, f := range d.Fields {
		req := ""
		if f.Required {
			req = " required"
		}
		fmt.Fprintf(&b, "  <label>%s\n", f.Label)
		switch f.Type {
		case forms.TypeTextarea:
			fmt.Fprintf(&b, "    <textarea name=\"%s\" maxlength=\"%d\"%s></textarea>\n", f.Name, f.Max, req)
		case forms.TypeEmail:
			fmt.Fprintf(&b, "    <input type=\"email\" name=\"%s\" maxlength=\"%d\"%s>\n", f.Name, f.Max, req)
		default:
			fmt.Fprintf(&b, "    <input type=\"text\" name=\"%s\" maxlength=\"%d\"%s>\n", f.Name, f.Max, req)
		}
		b.WriteString("  </label>\n")
	}
	if d.Honeypot != "" {
		fmt.Fprintf(&b, "  <!-- pułapka na boty: ukryj to pole CSS-em, nie przez type=hidden -->\n  <div style=\"position:absolute;left:-10000px\" aria-hidden=\"true\">\n    <input type=\"text\" name=\"%s\" tabindex=\"-1\" autocomplete=\"off\">\n  </div>\n", d.Honeypot)
	}
	b.WriteString("  <button type=\"submit\">Wyślij</button>\n  <p data-formd-status role=\"status\"></p>\n</form>\n")
	if d.Challenge {
		b.WriteString("<script src=\"/f/formd.js\" defer></script>\n")
	}
	a.render(w, r, http.StatusOK, "snippet", view{Title: "Kod HTML: " + d.Title, Session: s, Data: map[string]any{"Def": d, "HTML": b.String()}})
}

// ---- submissions ----

const pageSize = 50

func (a *Admin) submissions(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(page, 0)
	subs, err := a.Store.ListSubmissions(r.Context(), d.ID, time.Unix(0, 0), pageSize+1, page*pageSize)
	if err != nil {
		a.serverError(w, err)
		return
	}
	more := len(subs) > pageSize
	if more {
		subs = subs[:pageSize]
	}
	a.render(w, r, http.StatusOK, "submissions", view{Title: "Zgłoszenia: " + d.Title, Session: s, Data: map[string]any{
		"Def": d, "Subs": subs, "Page": page, "More": more,
	}})
}

func (a *Admin) deleteSubmission(w http.ResponseWriter, r *http.Request, s *store.Session) {
	id, sid := r.PathValue("id"), r.PathValue("sid")
	if err := a.Store.DeleteSubmission(r.Context(), id, sid); err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "submission_delete", id+"/"+sid)
	http.Redirect(w, r, "/forms/"+url.PathEscape(id)+"/submissions?ok=deleted", http.StatusSeeOther)
}

// csvSafe neutralises spreadsheet formula injection (=, +, -, @, tab, CR).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (a *Admin) exportCSV(w http.ResponseWriter, r *http.Request, s *store.Session) {
	d, ok := a.loadDef(w, r)
	if !ok {
		return
	}
	subs, err := a.Store.ListSubmissions(r.Context(), d.ID, time.Unix(0, 0), 1_000_000, 0)
	if err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "export_csv", fmt.Sprintf("%s rows=%d", d.ID, len(subs)))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", d.ID+"-"+time.Now().Format("20060102")+".csv"))
	cw := csv.NewWriter(w)
	WriteCSV(cw, d, subs)
	cw.Flush()
}

// WriteCSV writes submissions with columns in the form's field order.
func WriteCSV(cw *csv.Writer, d forms.Definition, subs []store.Submission) error {
	head := []string{"id", "created_at", "ip"}
	for _, f := range d.Fields {
		head = append(head, f.Name)
	}
	if err := cw.Write(head); err != nil {
		return err
	}
	for _, sub := range subs {
		row := []string{sub.ID, sub.CreatedAt.UTC().Format(time.RFC3339), sub.IP}
		for _, f := range d.Fields {
			row = append(row, csvSafe(sub.Data[f.Name]))
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// ---- outbox ----

func (a *Admin) outbox(w http.ResponseWriter, r *http.Request, s *store.Session) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "sent", "failed":
	default:
		status = ""
	}
	items, err := a.Store.RecentOutbox(r.Context(), status, 200)
	if err != nil {
		a.serverError(w, err)
		return
	}
	a.render(w, r, http.StatusOK, "outbox", view{Title: "Kolejka maili", Session: s, Data: map[string]any{"Items": items, "Status": status}})
}

func (a *Admin) retry(w http.ResponseWriter, r *http.Request, s *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("oid"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.Store.Requeue(r.Context(), id); err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "outbox_requeue", strconv.FormatInt(id, 10))
	http.Redirect(w, r, "/outbox?status=failed&ok=requeued", http.StatusSeeOther)
}

// ---- audit ----

func (a *Admin) auditPage(w http.ResponseWriter, r *http.Request, s *store.Session) {
	entries, err := a.Store.ListAudit(r.Context(), 500)
	if err != nil {
		a.serverError(w, err)
		return
	}
	a.render(w, r, http.StatusOK, "audit", view{Title: "Dziennik zdarzeń", Session: s, Data: entries})
}

// ---- account ----

func (a *Admin) accountPage(w http.ResponseWriter, r *http.Request, s *store.Session) {
	a.render(w, r, http.StatusOK, "account", view{Title: "Konto", Session: s})
}

func (a *Admin) accountSubmit(w http.ResponseWriter, r *http.Request, s *store.Session) {
	cur, n1, n2 := r.PostForm.Get("current"), r.PostForm.Get("new"), r.PostForm.Get("confirm")
	fail := func(msg string) {
		a.render(w, r, http.StatusBadRequest, "account", view{Title: "Konto", Session: s, Error: msg})
	}
	if !a.limiter.Allow("pw|"+s.Username, 5, 15*time.Minute, time.Now()) {
		fail("Zbyt wiele prób. Spróbuj później.")
		return
	}
	u, err := a.Store.UserByName(r.Context(), s.Username)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if !VerifyPassword(u.PasswordHash, cur) {
		a.audit(r, s.Username, "password_change_failed", "")
		fail("Obecne hasło jest nieprawidłowe.")
		return
	}
	if n1 != n2 {
		fail("Nowe hasła nie są identyczne.")
		return
	}
	if err := CheckPasswordPolicy(n1); err != nil {
		fail(err.Error())
		return
	}
	hash, err := HashPassword(n1)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if err := a.Store.SetPassword(r.Context(), s.Username, hash); err != nil {
		a.serverError(w, err)
		return
	}
	a.audit(r, s.Username, "password_change", "")
	a.clearCookie(w)
	http.Redirect(w, r, "/login?ok=password", http.StatusSeeOther)
}
