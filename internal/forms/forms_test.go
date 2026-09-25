package forms

import (
	"net/url"
	"strings"
	"testing"
)

func testForm(t *testing.T) *Form {
	t.Helper()
	d := NewDefinition("contact")
	d.AllowedOrigins = []string{"https://Example.com/"}
	d.Notify = []string{"owner@example.com"}
	f, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCompileRejectsUnsafeConfig(t *testing.T) {
	base := NewDefinition("contact")
	base.AllowedOrigins = []string{"https://example.com"}

	bad := map[string]func(d *Definition){
		"bad id":             func(d *Definition) { d.ID = "../etc" },
		"no origin":          func(d *Definition) { d.AllowedOrigins = nil },
		"origin with path":   func(d *Definition) { d.AllowedOrigins = []string{"https://example.com/x"} },
		"javascript origin":  func(d *Definition) { d.AllowedOrigins = []string{"javascript:alert(1)"} },
		"header in notify":   func(d *Definition) { d.Notify = []string{"a@example.com\r\nBcc: x@evil.com"} },
		"display name":       func(d *Definition) { d.Notify = []string{"Evil <a@example.com>"} },
		"reply-to non email": func(d *Definition) { d.ReplyToField = "name" },
		"confirm no limit":   func(d *Definition) { d.ConfirmEnabled = true; d.ConfirmPerRecipientDay = 0 },
		"min time w/o chal":  func(d *Definition) { d.Challenge = false },
		"pow too hard":       func(d *Definition) { d.PowBits = 40 },
		"bad redirect":       func(d *Definition) { d.RedirectSuccess = "javascript:alert(1)" },
		"bad template":       func(d *Definition) { d.NotifySubject = "{{.x" },
		"dup field":          func(d *Definition) { d.Fields = append(d.Fields, d.Fields[0]) },
		"honeypot is field":  func(d *Definition) { d.Honeypot = "name" },
	}
	for name, mut := range bad {
		d := base
		d.Fields = append([]Field{}, base.Fields...)
		mut(&d)
		if _, err := Compile(d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f, err := Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	if !f.OriginAllowed("https://EXAMPLE.com") || f.OriginAllowed("https://evil.com") || f.OriginAllowed("") {
		t.Error("origin matching wrong")
	}
}

func TestValidate(t *testing.T) {
	f := testForm(t)
	ok := url.Values{"name": {"Jan"}, "email": {"jan@example.com"}, "message": {"Cześć\r\nlinia 2"}}
	res := f.Validate(ok)
	if !res.OK() || res.Spam != "" {
		t.Fatalf("valid rejected: %+v", res)
	}
	if res.Values["message"] != "Cześć\nlinia 2" {
		t.Errorf("newline not normalised: %q", res.Values["message"])
	}

	cases := map[string]url.Values{
		"unknown field":   {"name": {"a"}, "email": {"a@b.pl"}, "message": {"x"}, "admin": {"1"}},
		"missing":         {"name": {"a"}, "message": {"x"}},
		"newline in text": {"name": {"a\nBcc: x@y.z"}, "email": {"a@b.pl"}, "message": {"x"}},
		"control char":    {"name": {"a\x1b[31m"}, "email": {"a@b.pl"}, "message": {"x"}},
		"bidi override":   {"name": {"a‮b"}, "email": {"a@b.pl"}, "message": {"x"}},
		"bad email":       {"name": {"a"}, "email": {"a@b.pl\r\nBcc: v@x.y"}, "message": {"x"}},
		"email with name": {"name": {"a"}, "email": {"A <a@b.pl>"}, "message": {"x"}},
		"too long":        {"name": {strings.Repeat("ą", 201)}, "email": {"a@b.pl"}, "message": {"x"}},
		"invalid utf8":    {"name": {"\xff\xfe"}, "email": {"a@b.pl"}, "message": {"x"}},
	}
	for name, in := range cases {
		if r := f.Validate(in); r.OK() {
			t.Errorf("%s: accepted", name)
		}
	}

	spam := map[string]url.Values{
		"honeypot": {"name": {"a"}, "email": {"a@b.pl"}, "message": {"x"}, "website": {"http://x"}},
		"links":    {"name": {"a"}, "email": {"a@b.pl"}, "message": {"http://a http://b https://c"}},
	}
	for name, in := range spam {
		if r := f.Validate(in); r.Spam == "" {
			t.Errorf("%s: not flagged as spam", name)
		}
	}
}

func TestRenderSubjectIsSingleLine(t *testing.T) {
	d := NewDefinition("contact")
	d.AllowedOrigins = []string{"https://example.com"}
	d.NotifySubject = "Od: {{.message}}"
	f, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.RenderNotify(map[string]string{"message": "hej\nBcc: evil@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(r.Subject, "\r\n") {
		t.Fatalf("subject contains newline: %q", r.Subject)
	}
}

func TestConfirmHTMLEscapes(t *testing.T) {
	d := NewDefinition("contact")
	d.AllowedOrigins = []string{"https://example.com"}
	d.ConfirmEnabled = true
	d.ConfirmHTML = "<p>Cześć {{.name}}</p>"
	f, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.RenderConfirm(map[string]string{"name": `<script>alert(1)</script>`})
	if strings.Contains(r.HTML, "<script>") {
		t.Fatalf("HTML not escaped: %s", r.HTML)
	}
}
