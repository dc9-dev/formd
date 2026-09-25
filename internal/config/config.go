// Package config loads process-wide settings from the environment (.env).
// Per-form settings live in the database and are edited in the admin panel.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/dc9-dev/formd/internal/netutil"
)

type Rate struct {
	N      int
	Window time.Duration
}

func (r Rate) String() string { return fmt.Sprintf("%d/%s", r.N, r.Window) }

type SMTP struct {
	Host string
	Port int
	User string
	Pass string
	TLS  string // starttls | tls | none
}

type Config struct {
	ListenAddr      string
	AllowedIPs      []netip.Prefix
	TrustedProxies  []netip.Prefix
	AdminListenAddr string
	AdminAllowedIPs []netip.Prefix
	// AdminHosts are accepted Host header names for the panel (DNS-rebinding protection).
	AdminHosts []string

	DBPath string

	Mailer    string // smtp | ses | log
	MailFrom  *mail.Address
	SMTP      SMTP
	AWSRegion string

	MaxBody           int64
	GlobalRatePerIP   Rate // across all forms
	ChallengeRate     Rate // challenge issuance per IP
	MailHourlyCap     int  // max e-mails sent per hour, all forms together
	AdminCookieSecure bool
	SessionTTL        time.Duration
	SessionIdle       time.Duration
	LogLevel          string
}

// Load reads envFile (if it exists) into the environment without overriding
// variables that are already set, then builds and validates the Config.
func Load(envFile string) (*Config, error) {
	if envFile != "" {
		if err := godotenv.Load(envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("reading %s: %w", envFile, err)
		}
	}
	e := &envReader{}
	c := &Config{
		ListenAddr:        e.str("LISTEN_ADDR", "127.0.0.1:8025"),
		AllowedIPs:        e.prefixes("ALLOWED_IPS", "127.0.0.1,::1"),
		TrustedProxies:    e.prefixes("TRUSTED_PROXIES", "127.0.0.1,::1"),
		AdminListenAddr:   e.str("ADMIN_LISTEN_ADDR", "127.0.0.1:8026"),
		AdminAllowedIPs:   e.prefixes("ADMIN_ALLOWED_IPS", "127.0.0.1,::1"),
		AdminHosts:        e.list("ADMIN_HOSTS", "localhost,127.0.0.1,::1"),
		DBPath:            e.str("DB_PATH", "formd.db"),
		Mailer:            e.str("MAILER", "log"),
		AWSRegion:         e.str("AWS_REGION", ""),
		MaxBody:           e.size("MAX_BODY", "64KB"),
		GlobalRatePerIP:   e.rate("GLOBAL_RATE_PER_IP", "20/1h"),
		ChallengeRate:     e.rate("CHALLENGE_RATE_PER_IP", "30/10m"),
		MailHourlyCap:     e.int("MAIL_HOURLY_CAP", 300),
		AdminCookieSecure: e.bool("ADMIN_COOKIE_SECURE", true),
		SessionTTL:        e.dur("ADMIN_SESSION_TTL", "12h"),
		SessionIdle:       e.dur("ADMIN_SESSION_IDLE", "1h"),
		LogLevel:          e.str("LOG_LEVEL", "info"),
		SMTP: SMTP{
			Host: e.str("SMTP_HOST", ""),
			Port: e.int("SMTP_PORT", 587),
			User: e.str("SMTP_USER", ""),
			Pass: e.str("SMTP_PASS", ""),
			TLS:  e.str("SMTP_TLS", "starttls"),
		},
	}
	if from := e.str("MAIL_FROM", ""); from != "" {
		a, err := mail.ParseAddress(from)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("MAIL_FROM: %w", err))
		} else {
			c.MailFrom = a
		}
	}
	if len(e.errs) > 0 {
		return nil, errors.Join(e.errs...)
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	if _, err := netutil.CheckListenAddr(c.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("LISTEN_ADDR: %w", err))
	}
	if c.AdminListenAddr != "" && c.AdminListenAddr != "off" {
		if _, err := netutil.CheckListenAddr(c.AdminListenAddr); err != nil {
			errs = append(errs, fmt.Errorf("ADMIN_LISTEN_ADDR: %w", err))
		}
		if c.AdminListenAddr == c.ListenAddr {
			errs = append(errs, errors.New("ADMIN_LISTEN_ADDR must differ from LISTEN_ADDR"))
		}
	}
	if len(c.AllowedIPs) == 0 {
		errs = append(errs, errors.New("ALLOWED_IPS must not be empty"))
	}
	if len(c.AdminAllowedIPs) == 0 {
		errs = append(errs, errors.New("ADMIN_ALLOWED_IPS must not be empty"))
	}
	switch c.Mailer {
	case "log":
	case "smtp":
		if c.SMTP.Host == "" {
			errs = append(errs, errors.New("SMTP_HOST is required for MAILER=smtp"))
		}
		switch c.SMTP.TLS {
		case "starttls", "tls", "none":
		default:
			errs = append(errs, fmt.Errorf("SMTP_TLS must be starttls, tls or none, got %q", c.SMTP.TLS))
		}
	case "ses":
	default:
		errs = append(errs, fmt.Errorf("MAILER must be smtp, ses or log, got %q", c.Mailer))
	}
	if c.Mailer != "log" && c.MailFrom == nil {
		errs = append(errs, errors.New("MAIL_FROM is required"))
	}
	if c.MailFrom == nil {
		c.MailFrom = &mail.Address{Name: "formd", Address: "formd@localhost"}
	}
	if c.MaxBody < 1024 || c.MaxBody > 10<<20 {
		errs = append(errs, errors.New("MAX_BODY must be between 1KB and 10MB"))
	}
	return errors.Join(errs...)
}

// AdminEnabled reports whether the admin panel listener should start.
func (c *Config) AdminEnabled() bool {
	return c.AdminListenAddr != "" && c.AdminListenAddr != "off"
}

type envReader struct{ errs []error }

func (e *envReader) str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func (e *envReader) list(key, def string) []string {
	var out []string
	for _, v := range strings.Split(e.str(key, def), ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (e *envReader) int(key string, def int) int {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid non-negative integer %q", key, v))
	}
	return n
}

func (e *envReader) bool(key string, def bool) bool {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid boolean %q", key, v))
	}
	return b
}

func (e *envReader) dur(key, def string) time.Duration {
	v := e.str(key, def)
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid duration %q", key, v))
	}
	return d
}

func (e *envReader) prefixes(key, def string) []netip.Prefix {
	p, err := netutil.ParsePrefixes(e.str(key, def))
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
	}
	return p
}

func (e *envReader) rate(key, def string) Rate {
	v := e.str(key, def)
	r, err := ParseRate(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
	}
	return r
}

func (e *envReader) size(key, def string) int64 {
	v := strings.ToUpper(e.str(key, def))
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "MB"):
		mult, v = 1<<20, strings.TrimSuffix(v, "MB")
	case strings.HasSuffix(v, "KB"):
		mult, v = 1<<10, strings.TrimSuffix(v, "KB")
	case strings.HasSuffix(v, "B"):
		v = strings.TrimSuffix(v, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid size", key))
	}
	return n * mult
}

// ParseRate parses "N/duration", e.g. "5/10m". N=0 disables the limit.
func ParseRate(s string) (Rate, error) {
	n, w, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return Rate{}, fmt.Errorf("invalid rate %q, expected N/duration like 5/10m", s)
	}
	cnt, err := strconv.Atoi(n)
	if err != nil || cnt < 0 {
		return Rate{}, fmt.Errorf("invalid rate count in %q", s)
	}
	d, err := time.ParseDuration(w)
	if err != nil || d <= 0 {
		return Rate{}, fmt.Errorf("invalid rate window in %q", s)
	}
	return Rate{N: cnt, Window: d}, nil
}
