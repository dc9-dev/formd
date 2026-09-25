package antispam

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"
)

func solve(token string, bits int) string {
	for n := 0; ; n++ {
		s := strconv.Itoa(n)
		if CheckPow(token, s, bits) {
			return s
		}
	}
}

func TestChallenge(t *testing.T) {
	c, err := NewChallenger(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_700_000_000, 0)
	tok := c.Issue("contact", 10, t0)
	pow := solve(tok, 10)

	if _, err := c.Verify(tok, pow, "contact", 10, 3*time.Second, t0.Add(5*time.Second)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	checks := []struct {
		name    string
		tok     string
		pow     string
		form    string
		minBits int
		at      time.Time
		want    error
	}{
		{"missing", "", pow, "contact", 10, t0.Add(5 * time.Second), ErrChallengeMissing},
		{"other form", tok, pow, "other", 10, t0.Add(5 * time.Second), ErrChallengeInvalid},
		{"too fast", tok, pow, "contact", 10, t0.Add(time.Second), ErrChallengeTooNew},
		{"expired", tok, pow, "contact", 10, t0.Add(3 * time.Hour), ErrChallengeExpired},
		{"difficulty raised", tok, pow, "contact", 12, t0.Add(5 * time.Second), ErrChallengeExpired},
		{"bad pow", tok, "x", "contact", 10, t0.Add(5 * time.Second), ErrPowInvalid},
		{"tampered", strings.Replace(tok, tok[3:4], string(rune(tok[3]^1)), 1), pow, "contact", 10, t0.Add(5 * time.Second), ErrChallengeInvalid},
	}
	for _, k := range checks {
		if _, err := c.Verify(k.tok, k.pow, k.form, k.minBits, 3*time.Second, k.at); err != k.want {
			t.Errorf("%s: got %v want %v", k.name, err, k.want)
		}
	}

	other, _ := NewChallenger(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Verify(tok, pow, "contact", 10, 0, t0.Add(5*time.Second)); err != ErrChallengeInvalid {
		t.Errorf("foreign key accepted: %v", err)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	if n := LeadingZeroBits([]byte{0, 0x0f}); n != 12 {
		t.Fatal(n)
	}
	if n := LeadingZeroBits([]byte{0x80}); n != 0 {
		t.Fatal(n)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2)
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if !l.Allow("a", 3, time.Minute, now) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.Allow("a", 3, time.Minute, now) {
		t.Fatal("4th request allowed")
	}
	if !l.Allow("a", 3, time.Minute, now.Add(21*time.Second)) {
		t.Fatal("refill did not happen")
	}
	// Table full: new key refused while existing buckets still hold state.
	l.Allow("b", 3, time.Minute, now)
	if l.Allow("c", 3, time.Minute, now) {
		t.Fatal("key table grew past max")
	}
	// After refill, stale buckets are swept and space frees up.
	if !l.Allow("c", 3, time.Minute, now.Add(time.Hour)) {
		t.Fatal("sweep did not free space")
	}
}
