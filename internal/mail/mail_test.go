package mail

import (
	"mime"
	"net/mail"
	"strings"
	"testing"
	"time"
)

var from = &mail.Address{Name: "Strona", Address: "no-reply@example.com"}

func TestBuildRejectsHeaderInjection(t *testing.T) {
	bad := []Message{
		{From: from, To: "a@example.com\r\nBcc: x@evil.com", Subject: "s", Text: "t"},
		{From: from, To: "a@example.com", ReplyTo: "b@example.com\nBcc: x@evil.com", Subject: "s", Text: "t"},
		{From: from, To: "a@example.com", Subject: "s\r\nBcc: x@evil.com", Text: "t"},
	}
	for i, m := range bad {
		if _, err := Build(m, time.Now()); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestBuild(t *testing.T) {
	raw, err := Build(Message{From: from, To: "a@example.com", ReplyTo: "b@example.com", Subject: "Zażółć gęślą jaźń", Text: "linia\nlinia 2", HTML: "<p>x</p>"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("Reply-To"); got != "<b@example.com>" {
		t.Errorf("reply-to %q", got)
	}
	dec := new(mime.WordDecoder)
	if s, _ := dec.DecodeHeader(msg.Header.Get("Subject")); s != "Zażółć gęślą jaźń" {
		t.Errorf("subject %q", s)
	}
	if !strings.HasPrefix(msg.Header.Get("Content-Type"), "multipart/alternative") {
		t.Errorf("content-type %q", msg.Header.Get("Content-Type"))
	}
}
