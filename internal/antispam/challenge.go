// Package antispam implements the abuse controls that sit in front of form
// processing: signed single-use challenges with proof-of-work, and in-memory
// token-bucket rate limiting.
package antispam

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

var (
	ErrChallengeMissing = errors.New("challenge missing")
	ErrChallengeInvalid = errors.New("challenge invalid")
	ErrChallengeTooNew  = errors.New("form submitted too quickly")
	ErrChallengeExpired = errors.New("challenge expired")
	ErrPowInvalid       = errors.New("proof of work invalid")
)

// MaxChallengeAge bounds how long a page may stay open before submitting.
const MaxChallengeAge = 2 * time.Hour

// Challenger issues and verifies HMAC-signed challenge tokens.
//
// Token: base64url("v1|form|issuedUnix|bits|nonce") + "." + base64url(hmac).
// The server stores nothing at issue time; the nonce is recorded only when a
// token is spent, which makes tokens single-use without an issuance table
// that attackers could flood.
type Challenger struct{ key []byte }

func NewChallenger(key []byte) (*Challenger, error) {
	if len(key) < 32 {
		return nil, errors.New("challenge key must be at least 32 bytes")
	}
	return &Challenger{key: key}, nil
}

func (c *Challenger) Issue(formID string, powBits int, now time.Time) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	payload := fmt.Sprintf("v1|%s|%d|%d|%s", formID, now.Unix(), powBits, hex.EncodeToString(nonce))
	return b64(payload) + "." + b64(string(c.mac(payload)))
}

// Verified describes a successfully verified challenge.
type Verified struct {
	Nonce    string
	IssuedAt time.Time
}

// Verify checks signature, form binding, age window and proof-of-work.
// The caller must still record Nonce to prevent replay.
func (c *Challenger) Verify(token, pow, formID string, minBits int, minAge time.Duration, now time.Time) (Verified, error) {
	if token == "" {
		return Verified{}, ErrChallengeMissing
	}
	if len(token) > 512 {
		return Verified{}, ErrChallengeInvalid
	}
	p64, s64, ok := strings.Cut(token, ".")
	if !ok {
		return Verified{}, ErrChallengeInvalid
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p64)
	sig, err2 := base64.RawURLEncoding.DecodeString(s64)
	if err1 != nil || err2 != nil {
		return Verified{}, ErrChallengeInvalid
	}
	if !hmac.Equal(sig, c.mac(string(payload))) {
		return Verified{}, ErrChallengeInvalid
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != formID {
		return Verified{}, ErrChallengeInvalid
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Verified{}, ErrChallengeInvalid
	}
	tokenBits, err := strconv.Atoi(parts[3])
	if err != nil || tokenBits < minBits {
		// Difficulty was raised after issue; client must fetch a new one.
		return Verified{}, ErrChallengeExpired
	}
	issuedAt := time.Unix(issued, 0)
	age := now.Sub(issuedAt)
	if age < minAge {
		return Verified{}, ErrChallengeTooNew
	}
	if age > MaxChallengeAge || age < -time.Minute {
		return Verified{}, ErrChallengeExpired
	}
	if !CheckPow(token, pow, tokenBits) {
		return Verified{}, ErrPowInvalid
	}
	return Verified{Nonce: parts[4], IssuedAt: issuedAt}, nil
}

// CheckPow reports whether sha256(token + ":" + pow) starts with n zero bits.
// pow must be a short decimal counter.
func CheckPow(token, pow string, n int) bool {
	if n <= 0 {
		return true
	}
	if pow == "" || len(pow) > 20 {
		return false
	}
	for _, r := range pow {
		if r < '0' || r > '9' {
			return false
		}
	}
	sum := sha256.Sum256([]byte(token + ":" + pow))
	return LeadingZeroBits(sum[:]) >= n
}

func LeadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

func (c *Challenger) mac(payload string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
