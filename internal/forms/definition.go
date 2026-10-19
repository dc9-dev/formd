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

	"github.com/dc9-dev/formd/internal/i18n"
)

// What to do with a submission Jev flags as risky.
const (
	JevTag  = "tag"  // deliver, mark in panel and subject
	JevHold = "hold" // store, keep mails until approved in the panel
	JevDrop = "drop" // silently discard like other spam
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

	// Content assessment with Jev or a self-hosted basal model (sends field values to it).
	JevEnabled     bool   `json:"jev_enabled"`
	JevContext     string `json:"jev_context"`       // what the site is about; improves judgement
	JevAction      string `json:"jev_action"`        // tag | hold | drop
	JevThreshold   int    `json:"jev_threshold"`     // risk in percent at which a submission is flagged
	JevHoldOnError bool   `json:"jev_hold_on_error"` // hold submissions that could not be assessed

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
			{Name: "name", Label: i18n.T("Name"), Type: TypeText, Required: true, Max: 200},
			{Name: "email", Label: i18n.T("Email"), Type: TypeEmail, Required: true, Max: 254},
			{Name: "message", Label: i18n.T("Message"), Type: TypeTextarea, Required: true, Max: 5000},
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
		NotifySubject:          i18n.T("New submission from {{.name}}"),
		ReplyToField:           "email",
		ConfirmToField:         "email",
		ConfirmSubject:         i18n.T("Thanks for your message"),
		ConfirmText:            i18n.T("Hello,\n\nwe have received your message and will reply as soon as we can.\n"),
		ConfirmPerRecipientDay: 2,
		JevAction:              JevHold,
		JevThreshold:           70,
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
	add := func(format string, a ...any) { errs = append(errs, i18n.Errorf(format, a...)) }

	d.ID = strings.TrimSpace(d.ID)
	if !idRe.MatchString(d.ID) {
		add("ID: only lowercase letters, digits, '-' and '_' are allowed (max 64 characters)")
	}
	d.Title = strings.TrimSpace(d.Title)
	if utf8.RuneCountInString(d.Title) > 200 {
		add("name: max 200 characters")
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
			add("allowed origin %q: %v", o, err)
			continue
		}
		if !f.origins[n] {
			f.origins[n] = true
			origins = append(origins, n)
		}
	}
	d.AllowedOrigins = origins
	if len(origins) == 0 {
		add("enter at least one allowed origin (e.g. https://example.com)")
	}
	if len(origins) > maxOrigins {
		add("max %d origins", maxOrigins)
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
			add("field %q: the name must start with a letter; letters, digits, '-' and '_' are allowed", fl.Name)
			continue
		}
		if f.fields[fl.Name] != nil {
			add("field %q appears twice", fl.Name)
			continue
		}
		switch fl.Type {
		case TypeText, TypeTextarea, TypeEmail:
		case "":
			fl.Type = TypeText
		default:
			add("field %q: unknown type %q", fl.Name, fl.Type)
		}
		if fl.Max <= 0 {
			fl.Max = defaultMaxLen
		}
		if fl.Type == TypeEmail && fl.Max > 254 {
			fl.Max = 254
		}
		if fl.Max > maxFieldLen {
			add("field %q: the maximum length is %d", fl.Name, maxFieldLen)
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
		add("the form needs at least one field")
	}
	if len(fields) > maxFields {
		add("max %d fields", maxFields)
	}

	// Anti-abuse.
	d.Honeypot = strings.TrimSpace(d.Honeypot)
	if d.Honeypot != "" {
		if !fieldRe.MatchString(d.Honeypot) {
			add("honeypot: invalid field name")
		} else if f.fields[d.Honeypot] != nil {
			add("honeypot %q cannot also be a regular field", d.Honeypot)
		}
	}
	if d.PowBits < 0 || d.PowBits > maxPowBits {
		add("proof-of-work difficulty: 0–%d bits", maxPowBits)
	}
	if d.MinSeconds < 0 || d.MinSeconds > 3600 {
		add("minimum fill time: 0–3600 s")
	}
	if d.MinSeconds > 0 && !d.Challenge {
		add("the minimum fill time needs the challenge turned on (the time is measured on the server)")
	}
	if d.RatePerIP < 0 || d.RateWindowMin < 0 || (d.RatePerIP > 0 && d.RateWindowMin == 0) {
		add("per-IP limit: enter a number and a window in minutes")
	}
	if d.HourlyCap < 0 || d.DedupeHours < 0 || d.RetentionDays < 0 || d.ConfirmPerRecipientDay < 0 {
		add("limits cannot be negative")
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
			add("notification address %q: %v", n, i18n.T(err.Error()))
			continue
		}
		notify = append(notify, n)
	}
	d.Notify = notify
	if len(notify) > maxRecipients {
		add("max %d notification addresses", maxRecipients)
	}
	if d.ReplyToField = strings.TrimSpace(d.ReplyToField); d.ReplyToField != "" {
		if fl := f.fields[d.ReplyToField]; fl == nil || fl.Type != TypeEmail {
			add("the Reply-To field must be an email field")
		}
	}
	var err error
	if f.notifySubject, err = parseText(i18n.T("notification subject"), d.NotifySubject); err != nil {
		errs = append(errs, err)
	}

	// Confirmation to the sender.
	if d.ConfirmEnabled {
		if fl := f.fields[strings.TrimSpace(d.ConfirmToField)]; fl == nil || fl.Type != TypeEmail {
			add("confirmation: the recipient field must be an email field")
		}
		if strings.TrimSpace(d.ConfirmSubject) == "" || strings.TrimSpace(d.ConfirmText) == "" {
			add("confirmation: the subject and the text body are required")
		}
		if d.ConfirmPerRecipientDay == 0 {
			add("confirmation: the daily limit per address must be greater than 0 (protection against mail bombing)")
		}
	}
	d.ConfirmToField = strings.TrimSpace(d.ConfirmToField)
	if f.confirmSubject, err = parseText(i18n.T("confirmation subject"), d.ConfirmSubject); err != nil {
		errs = append(errs, err)
	}
	if f.confirmText, err = parseText(i18n.T("confirmation text"), d.ConfirmText); err != nil {
		errs = append(errs, err)
	}
	if len(d.ConfirmHTML) > maxTemplateLen {
		add("confirmation HTML body: max %d characters", maxTemplateLen)
	} else if strings.TrimSpace(d.ConfirmHTML) != "" {
		t, err := htemplate.New("confirm_html").Option("missingkey=zero").Parse(d.ConfirmHTML)
		if err != nil {
			add("confirmation HTML body: %v", err)
		}
		f.confirmHTML = t
	}

	// Content assessment.
	d.JevContext = strings.TrimSpace(d.JevContext)
	if utf8.RuneCountInString(d.JevContext) > 300 {
		add("site description for content assessment: max 300 characters")
	}
	switch d.JevAction {
	case JevTag, JevHold, JevDrop:
	case "":
		d.JevAction = JevHold
	default:
		add("content assessment: unknown action %q", d.JevAction)
	}
	if d.JevThreshold == 0 {
		d.JevThreshold = 70
	}
	if d.JevThreshold < 1 || d.JevThreshold > 100 {
		add("content assessment: the risk threshold must be between 1 and 100%%")
	}

	for _, r := range []struct{ name, v string }{{i18n.T("redirect after success"), d.RedirectSuccess}, {i18n.T("redirect after an error"), d.RedirectError}} {
		if strings.TrimSpace(r.v) == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(r.v))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			add("%s: a full http(s):// address is required", r.name)
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
		return nil, i18n.Errorf("%s: max %d characters", name, maxTemplateLen)
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
		return "", errors.New(i18n.T("the scheme must be http or https"))
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New(i18n.T("enter the origin only, e.g. https://example.com"))
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// ErrInvalidEmail is returned by ParseEmail; its text is an i18n key.
var ErrInvalidEmail = errors.New("invalid email address")

// ParseEmail accepts a bare address only (no display name, no header tricks).
func ParseEmail(s string) (string, error) {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n\x00<>\",;") {
		return "", ErrInvalidEmail
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", ErrInvalidEmail
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 || !strings.Contains(s[at+1:], ".") {
		return "", ErrInvalidEmail
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
		subj = CleanHeader(i18n.T("New submission: ")+f.Def.Title, 200)
	}
	var b strings.Builder
	fmt.Fprintf(&b, i18n.T("Form: %s (%s)\n\n"), f.Def.Title, f.Def.ID)
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
