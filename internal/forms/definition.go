// Package forms defines a form's configuration (edited in the admin panel),
// compiles it into a validated, ready-to-use Form, and validates submissions.
package forms

import (
	"bytes"
	"errors"
	"fmt"
	htemplate "html/template"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	ttemplate "text/template"
	"unicode/utf8"
)

const (
	TypeText     = "text"
	TypeTextarea = "textarea"
	TypeEmail    = "email"

	maxFields      = 50
	maxFieldLen    = 100_000
	defaultMaxLen  = 1000
	maxRecipients  = 20
	maxOrigins     = 20
	maxTemplateLen = 20_000
	maxPowBits     = 24
)

var (
	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	fieldRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
)

// Reserved request fields used by the anti-abuse layer.
const (
	FieldChallenge = "_challenge"
	FieldPow       = "_pow"
)

type Field struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Max      int    `json:"max"`
}

// Definition is the persisted, admin-editable configuration of one form.
type Definition struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins"`
	Fields         []Field  `json:"fields"`

	// Anti-abuse.
	Honeypot      string   `json:"honeypot"`
	Challenge     bool     `json:"challenge"`       // require a signed, single-use token from /f/{id}/challenge
	PowBits       int      `json:"pow_bits"`        // proof-of-work difficulty (leading zero bits), 0 = token only
	MinSeconds    int      `json:"min_seconds"`     // min time between challenge issue and submit
	RatePerIP     int      `json:"rate_per_ip"`     // submissions per IP per window, 0 = off
	RateWindowMin int      `json:"rate_window_min"` // window in minutes
	HourlyCap     int      `json:"hourly_cap"`      // accepted submissions per hour for this form, 0 = off
	MaxLinks      int      `json:"max_links"`       // -1 = unlimited
	BlockedWords  []string `json:"blocked_words"`
	DedupeHours   int      `json:"dedupe_hours"` // drop identical submissions within N hours, 0 = off
	RetentionDays int      `json:"retention_days"`

	// Mail.
	Notify                 []string `json:"notify"`
	NotifySubject          string   `json:"notify_subject"`
	ReplyToField           string   `json:"reply_to_field"`
	ConfirmEnabled         bool     `json:"confirm_enabled"`
	ConfirmToField         string   `json:"confirm_to_field"`
	ConfirmSubject         string   `json:"confirm_subject"`
	ConfirmText            string   `json:"confirm_text"`
	ConfirmHTML            string   `json:"confirm_html"`
	ConfirmPerRecipientDay int      `json:"confirm_per_recipient_day"`

	RedirectSuccess string `json:"redirect_success"`
	RedirectError   string `json:"redirect_error"`
}

// NewDefinition returns a definition with safe defaults for a new form.
func NewDefinition(id string) Definition {
	return Definition{
		ID:      id,
		Title:   id,
		Enabled: false,
		Fields: []Field{
			{Name: "name", Label: "Imię", Type: TypeText, Required: true, Max: 200},
			{Name: "email", Label: "E-mail", Type: TypeEmail, Required: true, Max: 254},
			{Name: "message", Label: "Wiadomość", Type: TypeTextarea, Required: true, Max: 5000},
		},
		Honeypot:               "website",
		Challenge:              true,
		PowBits:                16,
		MinSeconds:             3,
		RatePerIP:              5,
		RateWindowMin:          10,
		HourlyCap:              60,
		MaxLinks:               2,
		DedupeHours:            24,
		RetentionDays:          365,
		NotifySubject:          "Nowe zgłoszenie z formularza {{.name}}",
		ReplyToField:           "email",
		ConfirmToField:         "email",
		ConfirmSubject:         "Dziękujemy za wiadomość",
		ConfirmText:            "Dzień dobry,\n\notrzymaliśmy Twoją wiadomość i odpowiemy najszybciej, jak to możliwe.\n",
		ConfirmPerRecipientDay: 2,
	}
}

// Form is a compiled, validated Definition. It is immutable once built.
type Form struct {
	Def     Definition
	origins map[string]bool
	fields  map[string]*Field

	notifySubject  *ttemplate.Template
	confirmSubject *ttemplate.Template
	confirmText    *ttemplate.Template
	confirmHTML    *htemplate.Template
}

// Compile normalises and validates d. All errors are returned together so the
// admin panel can show them at once.
func Compile(d Definition) (*Form, error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	d.ID = strings.TrimSpace(d.ID)
	if !idRe.MatchString(d.ID) {
		add("identyfikator: dozwolone małe litery, cyfry, '-' i '_' (max 64 znaki)")
	}
	d.Title = strings.TrimSpace(d.Title)
	if utf8.RuneCountInString(d.Title) > 200 {
		add("nazwa: max 200 znaków")
	}

	f := &Form{origins: map[string]bool{}, fields: map[string]*Field{}}

	// Origins.
	var origins []string
	for _, o := range d.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		n, err := normalizeOrigin(o)
		if err != nil {
			add("dozwolony origin %q: %v", o, err)
			continue
		}
		if !f.origins[n] {
			f.origins[n] = true
			origins = append(origins, n)
		}
	}
	d.AllowedOrigins = origins
	if len(origins) == 0 {
		add("podaj co najmniej jeden dozwolony origin (np. https://example.com)")
	}
	if len(origins) > maxOrigins {
		add("max %d originów", maxOrigins)
	}

	// Fields.
	var fields []Field
	for _, fl := range d.Fields {
		fl.Name = strings.TrimSpace(fl.Name)
		if fl.Name == "" {
			continue
		}
		fl.Label = strings.TrimSpace(fl.Label)
		if fl.Label == "" {
			fl.Label = fl.Name
		}
		if !fieldRe.MatchString(fl.Name) {
			add("pole %q: nazwa musi zaczynać się literą; dozwolone litery, cyfry, '-' i '_'", fl.Name)
			continue
		}
		if f.fields[fl.Name] != nil {
			add("pole %q występuje dwa razy", fl.Name)
			continue
		}
		switch fl.Type {
		case TypeText, TypeTextarea, TypeEmail:
		case "":
			fl.Type = TypeText
		default:
			add("pole %q: nieznany typ %q", fl.Name, fl.Type)
		}
		if fl.Max <= 0 {
			fl.Max = defaultMaxLen
		}
		if fl.Type == TypeEmail && fl.Max > 254 {
			fl.Max = 254
		}
		if fl.Max > maxFieldLen {
			add("pole %q: max długość to %d", fl.Name, maxFieldLen)
		}
		fields = append(fields, fl)
		f.fields[fl.Name] = &fields[len(fields)-1]
	}
	d.Fields = fields
	// Re-point map entries: append may have reallocated the slice.
	for i := range d.Fields {
		f.fields[d.Fields[i].Name] = &d.Fields[i]
	}
	if len(fields) == 0 {
		add("formularz musi mieć co najmniej jedno pole")
	}
	if len(fields) > maxFields {
		add("max %d pól", maxFields)
	}

	// Anti-abuse.
	d.Honeypot = strings.TrimSpace(d.Honeypot)
	if d.Honeypot != "" {
		if !fieldRe.MatchString(d.Honeypot) {
			add("honeypot: nieprawidłowa nazwa pola")
		} else if f.fields[d.Honeypot] != nil {
			add("honeypot %q nie może być jednocześnie zwykłym polem", d.Honeypot)
		}
	}
	if d.PowBits < 0 || d.PowBits > maxPowBits {
		add("trudność proof-of-work: 0–%d bitów", maxPowBits)
	}
	if d.MinSeconds < 0 || d.MinSeconds > 3600 {
		add("minimalny czas wypełnienia: 0–3600 s")
	}
	if d.MinSeconds > 0 && !d.Challenge {
		add("minimalny czas wypełnienia wymaga włączonego challenge (czas jest liczony po stronie serwera)")
	}
	if d.RatePerIP < 0 || d.RateWindowMin < 0 || (d.RatePerIP > 0 && d.RateWindowMin == 0) {
		add("limit per IP: podaj liczbę i okno w minutach")
	}
	if d.HourlyCap < 0 || d.DedupeHours < 0 || d.RetentionDays < 0 || d.ConfirmPerRecipientDay < 0 {
		add("limity nie mogą być ujemne")
	}
	if d.MaxLinks < -1 {
		d.MaxLinks = -1
	}
	var words []string
	for _, w := range d.BlockedWords {
		w = strings.ToLower(strings.TrimSpace(w))
		if w != "" {
			words = append(words, w)
		}
	}
	d.BlockedWords = words

	// Notification.
	var notify []string
	for _, n := range d.Notify {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, err := ParseEmail(n); err != nil {
			add("adres powiadomień %q: %v", n, err)
			continue
		}
		notify = append(notify, n)
	}
	d.Notify = notify
	if len(notify) > maxRecipients {
		add("max %d adresów powiadomień", maxRecipients)
	}
	if d.ReplyToField = strings.TrimSpace(d.ReplyToField); d.ReplyToField != "" {
		if fl := f.fields[d.ReplyToField]; fl == nil || fl.Type != TypeEmail {
			add("pole Reply-To musi wskazywać pole typu e-mail")
		}
	}
	var err error
	if f.notifySubject, err = parseText("temat powiadomienia", d.NotifySubject); err != nil {
		errs = append(errs, err)
	}

	// Confirmation to the sender.
	if d.ConfirmEnabled {
		if fl := f.fields[strings.TrimSpace(d.ConfirmToField)]; fl == nil || fl.Type != TypeEmail {
			add("potwierdzenie: pole odbiorcy musi wskazywać pole typu e-mail")
		}
		if strings.TrimSpace(d.ConfirmSubject) == "" || strings.TrimSpace(d.ConfirmText) == "" {
			add("potwierdzenie: temat i treść tekstowa są wymagane")
		}
		if d.ConfirmPerRecipientDay == 0 {
			add("potwierdzenie: limit maili na adres dziennie musi być > 0 (ochrona przed mail-bombingiem)")
		}
	}
	d.ConfirmToField = strings.TrimSpace(d.ConfirmToField)
	if f.confirmSubject, err = parseText("temat potwierdzenia", d.ConfirmSubject); err != nil {
		errs = append(errs, err)
	}
	if f.confirmText, err = parseText("treść potwierdzenia", d.ConfirmText); err != nil {
		errs = append(errs, err)
	}
	if len(d.ConfirmHTML) > maxTemplateLen {
		add("treść HTML potwierdzenia: max %d znaków", maxTemplateLen)
	} else if strings.TrimSpace(d.ConfirmHTML) != "" {
		t, err := htemplate.New("confirm_html").Option("missingkey=zero").Parse(d.ConfirmHTML)
		if err != nil {
			add("treść HTML potwierdzenia: %v", err)
		}
		f.confirmHTML = t
	}

	for _, r := range []struct{ name, v string }{{"przekierowanie po sukcesie", d.RedirectSuccess}, {"przekierowanie po błędzie", d.RedirectError}} {
		if strings.TrimSpace(r.v) == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(r.v))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			add("%s: wymagany pełny adres http(s)://", r.name)
		}
	}
	d.RedirectSuccess = strings.TrimSpace(d.RedirectSuccess)
	d.RedirectError = strings.TrimSpace(d.RedirectError)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	f.Def = d
	return f, nil
}

func parseText(name, src string) (*ttemplate.Template, error) {
	if len(src) > maxTemplateLen {
		return nil, fmt.Errorf("%s: max %d znaków", name, maxTemplateLen)
	}
	t, err := ttemplate.New(name).Option("missingkey=zero").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return t, nil
}

func normalizeOrigin(o string) (string, error) {
	u, err := url.Parse(o)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("schemat musi być http lub https")
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("podaj sam origin, np. https://example.com")
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// ParseEmail accepts a bare address only (no display name, no header tricks).
func ParseEmail(s string) (string, error) {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n\x00<>\",;") {
		return "", errors.New("nieprawidłowy adres e-mail")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", errors.New("nieprawidłowy adres e-mail")
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 || !strings.Contains(s[at+1:], ".") {
		return "", errors.New("nieprawidłowy adres e-mail")
	}
	return s, nil
}

// OriginAllowed reports whether a browser Origin is configured for this form.
func (f *Form) OriginAllowed(origin string) bool {
	n, err := normalizeOrigin(origin)
	return err == nil && f.origins[n]
}

// Field returns the configured field by name.
func (f *Form) Field(name string) *Field { return f.fields[name] }

// Rendered e-mail content.
type Rendered struct {
	Subject string
	Text    string
	HTML    string
}

// RenderNotify builds the owner notification. The body is generated from the
// field list (not a template) so it always contains every field verbatim.
func (f *Form) RenderNotify(values map[string]string) (Rendered, error) {
	subj, err := execText(f.notifySubject, values)
	if err != nil {
		return Rendered{}, err
	}
	subj = CleanHeader(subj, 200)
	if subj == "" {
		subj = CleanHeader("Nowe zgłoszenie: "+f.Def.Title, 200)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Formularz: %s (%s)\n\n", f.Def.Title, f.Def.ID)
	for _, fl := range f.Def.Fields {
		fmt.Fprintf(&b, "%s:\n%s\n\n", fl.Label, values[fl.Name])
	}
	return Rendered{Subject: subj, Text: b.String()}, nil
}

// RenderConfirm builds the confirmation for the sender.
func (f *Form) RenderConfirm(values map[string]string) (Rendered, error) {
	var r Rendered
	var err error
	if r.Subject, err = execText(f.confirmSubject, values); err != nil {
		return r, err
	}
	r.Subject = CleanHeader(r.Subject, 200)
	if r.Text, err = execText(f.confirmText, values); err != nil {
		return r, err
	}
	if f.confirmHTML != nil {
		var buf bytes.Buffer
		if err := f.confirmHTML.Execute(&buf, values); err != nil {
			return r, err
		}
		r.HTML = buf.String()
	}
	return r, nil
}

func execText(t *ttemplate.Template, values map[string]string) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, values); err != nil {
		return "", err
	}
	return buf.String(), nil
}
