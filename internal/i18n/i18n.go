// Package i18n holds formd's user-facing text in English and Polish.
//
// English is the source: every message is written in English in the code and
// looked up in the Polish catalogue (pl.go) when Polish is selected. A message
// with no Polish entry falls back to English, never to an empty string.
//
// The panel, e-mails to the site owner and the CLI use the process default
// (FORMD_LANG). Messages shown to a site visitor use the visitor's language,
// passed explicitly with In.
package i18n

import (
	"fmt"
	"strings"
	"sync/atomic"
)

type Lang string

const (
	EN Lang = "en"
	PL Lang = "pl"
)

var current atomic.Value // Lang

func init() { current.Store(EN) }

// Parse accepts "en", "pl" and region or encoding variants such as "pl-PL"
// or "pl_PL.UTF-8".
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_."); i >= 0 {
		s = s[:i]
	}
	switch Lang(s) {
	case EN:
		return EN, true
	case PL:
		return PL, true
	}
	return EN, false
}

// SetDefault selects the language of the panel, owner e-mails and the CLI.
func SetDefault(l Lang) { current.Store(l) }

// Default returns the language set with SetDefault (English if never set).
func Default() Lang { return current.Load().(Lang) }

// In returns msg in language l.
func In(l Lang, msg string) string {
	if l == PL {
		if s, ok := pl[msg]; ok {
			return s
		}
	}
	return msg
}

// T returns msg in the default language.
func T(msg string) string { return In(Default(), msg) }

// Sprintf formats a translated format string in the default language.
func Sprintf(format string, a ...any) string { return fmt.Sprintf(T(format), a...) }

// Errorf is fmt.Errorf with the format translated to the default language.
func Errorf(format string, a ...any) error { return fmt.Errorf(T(format), a...) }

// Has reports whether msg has a Polish translation; tests use it to find
// strings that were added in English only.
func Has(msg string) bool { _, ok := pl[msg]; return ok }
