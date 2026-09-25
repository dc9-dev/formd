package forms

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrTooLarge    = errors.New("request body too large")
	ErrBadRequest  = errors.New("malformed request")
	ErrUnsupported = errors.New("unsupported content type")
)

// ParseRequest reads the submission body. The body must already be wrapped in
// http.MaxBytesReader by the caller. File uploads are rejected.
func ParseRequest(r *http.Request, maxBody int64) (url.Values, error) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, ErrUnsupported
	}
	switch ct {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, classify(err)
		}
		return r.PostForm, nil
	case "multipart/form-data":
		if err := r.ParseMultipartForm(maxBody); err != nil {
			return nil, classify(err)
		}
		defer r.MultipartForm.RemoveAll()
		if len(r.MultipartForm.File) > 0 {
			return nil, fmt.Errorf("%w: file uploads are not accepted", ErrBadRequest)
		}
		return url.Values(r.MultipartForm.Value), nil
	case "application/json":
		var raw map[string]json.RawMessage
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&raw); err != nil {
			return nil, classify(err)
		}
		if dec.More() {
			return nil, ErrBadRequest
		}
		out := url.Values{}
		for k, v := range raw {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, fmt.Errorf("%w: field %q must be a string", ErrBadRequest, k)
			}
			out.Set(k, s)
		}
		return out, nil
	}
	return nil, ErrUnsupported
}

func classify(err error) error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) || strings.Contains(err.Error(), "too large") {
		return ErrTooLarge
	}
	return ErrBadRequest
}

// Result of validating one submission against a Form.
type Result struct {
	Values    map[string]string // clean values of configured fields
	Errors    map[string]string // field -> message; "_form" for general errors
	Spam      string            // non-empty: silently drop, reason for logs
	Challenge string
	Pow       string
}

func (r *Result) OK() bool { return len(r.Errors) == 0 }

var linkRe = regexp.MustCompile(`(?i)(https?://|www\.|\[url|<a\s)`)

// Validate checks the submission against the form definition. It never trusts
// the client: unknown fields are rejected, lengths are counted in runes,
// control characters are refused, and newlines are only allowed in textareas.
func (f *Form) Validate(in url.Values) Result {
	res := Result{Values: map[string]string{}, Errors: map[string]string{}}

	for key := range in {
		switch {
		case key == FieldChallenge, key == FieldPow:
		case f.Def.Honeypot != "" && key == f.Def.Honeypot:
		case f.fields[key] != nil:
		default:
			res.Errors["_form"] = "nieznane pole: " + truncate(key, 64)
		}
	}
	if len(res.Errors) > 0 {
		return res
	}

	res.Challenge = in.Get(FieldChallenge)
	res.Pow = in.Get(FieldPow)

	if f.Def.Honeypot != "" && strings.TrimSpace(in.Get(f.Def.Honeypot)) != "" {
		res.Spam = "honeypot"
	}

	for _, fl := range f.Def.Fields {
		vals := in[fl.Name]
		if len(vals) > 20 {
			res.Errors[fl.Name] = "zbyt wiele wartości"
			continue
		}
		v := strings.Join(vals, ", ")
		v = strings.ReplaceAll(v, "\r\n", "\n")
		v = strings.TrimSpace(v)

		if !utf8.ValidString(v) {
			res.Errors[fl.Name] = "nieprawidłowe kodowanie znaków"
			continue
		}
		if msg := badChars(v, fl.Type == TypeTextarea); msg != "" {
			res.Errors[fl.Name] = msg
			continue
		}
		if v == "" {
			if fl.Required {
				res.Errors[fl.Name] = "pole wymagane"
			}
			continue
		}
		if utf8.RuneCountInString(v) > fl.Max {
			res.Errors[fl.Name] = fmt.Sprintf("maksymalnie %d znaków", fl.Max)
			continue
		}
		if fl.Type == TypeEmail {
			if _, err := ParseEmail(v); err != nil {
				res.Errors[fl.Name] = "nieprawidłowy adres e-mail"
				continue
			}
		}
		res.Values[fl.Name] = v
	}
	if !res.OK() || res.Spam != "" {
		return res
	}

	all := strings.ToLower(strings.Join(mapValues(res.Values), "\n"))
	if f.Def.MaxLinks >= 0 && len(linkRe.FindAllStringIndex(all, f.Def.MaxLinks+1)) > f.Def.MaxLinks {
		res.Spam = "too many links"
		return res
	}
	for _, w := range f.Def.BlockedWords {
		if strings.Contains(all, w) {
			res.Spam = "blocked word"
			return res
		}
	}
	return res
}

// badChars refuses control characters (header/log injection, invisible
// payloads). Tabs are allowed everywhere, newlines only in multi-line fields.
func badChars(v string, multiline bool) string {
	for _, r := range v {
		switch {
		case r == '\t':
		case r == '\n':
			if !multiline {
				return "pole nie może zawierać nowych linii"
			}
		case r == '\r', unicode.IsControl(r), r == '\u2028', r == '\u2029', r == '\ufeff':
			return "pole zawiera niedozwolone znaki"
		case unicode.In(r, unicode.Bidi_Control):
			return "pole zawiera niedozwolone znaki"
		}
	}
	return ""
}

// ContentHash identifies a submission's content for duplicate detection.
func ContentHash(formID string, values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(formID))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(strings.ToLower(values[k])))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// CleanHeader turns arbitrary text into a safe single-line header value.
func CleanHeader(s string, maxRunes int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes]) + "…"
	}
	return s
}
