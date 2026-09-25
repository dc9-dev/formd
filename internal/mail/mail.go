// Package mail builds RFC 5322 messages and delivers them via SMTP, Amazon
// SES (API v2) or a log-only sink for development.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/dc9-dev/formd/internal/config"
)

type Message struct {
	From    *mail.Address
	To      string
	ReplyTo string
	Subject string
	Text    string
	HTML    string
}

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// New returns the mailer selected in the configuration.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (Mailer, error) {
	switch cfg.Mailer {
	case "smtp":
		return &SMTP{cfg: cfg.SMTP}, nil
	case "ses":
		return NewSES(ctx, cfg.AWSRegion)
	case "log":
		return &Log{log: log}, nil
	}
	return nil, fmt.Errorf("unknown mailer %q", cfg.Mailer)
}

var errHeader = errors.New("header contains line break")

func headerSafe(vals ...string) error {
	for _, v := range vals {
		if strings.ContainsAny(v, "\r\n\x00") {
			return errHeader
		}
	}
	return nil
}

// Build renders m as a MIME message. Every header value is checked for line
// breaks, and addresses are re-parsed, so user input can never inject headers.
func Build(m Message, now time.Time) ([]byte, error) {
	if m.From == nil {
		return nil, errors.New("missing From")
	}
	if err := headerSafe(m.From.Name, m.From.Address, m.To, m.ReplyTo, m.Subject); err != nil {
		return nil, err
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return nil, fmt.Errorf("invalid To: %w", err)
	}
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", m.From.String())
	h("To", to.String())
	if m.ReplyTo != "" {
		rt, err := mail.ParseAddress(m.ReplyTo)
		if err != nil {
			return nil, fmt.Errorf("invalid Reply-To: %w", err)
		}
		h("Reply-To", rt.String())
	}
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", fmt.Sprintf("<%s@%s>", randHex(16), domainOf(m.From.Address)))
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")

	if m.HTML == "" {
		h("Content-Type", `text/plain; charset="utf-8"`)
		h("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := writeQP(&b, m.Text); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}

	mw := multipart.NewWriter(&b)
	h("Content-Type", fmt.Sprintf(`multipart/alternative; boundary="%s"`, mw.Boundary()))
	b.WriteString("\r\n")
	for _, part := range []struct{ ct, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ct + `; charset="utf-8"`},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		if err := writeQP(w, part.body); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeQP(w interface{ Write([]byte) (int, error) }, s string) error {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(s)); err != nil {
		return err
	}
	return qp.Close()
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "localhost"
}

// Log only logs messages; for development.
type Log struct{ log *slog.Logger }

func (l *Log) Send(_ context.Context, m Message) error {
	if _, err := Build(m, time.Now()); err != nil {
		return err
	}
	l.log.Info("mail (MAILER=log, not sent)", "to", m.To, "reply_to", m.ReplyTo, "subject", m.Subject, "text", m.Text, "has_html", m.HTML != "")
	return nil
}
