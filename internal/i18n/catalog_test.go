package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every message that goes through the catalogue must have a Polish entry,
// otherwise Polish users would see English text. This scans the sources for
// the call shapes that take a catalogue key.
var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`i18n\.(?:T|Errorf|Sprintf)\("((?:[^"\\]|\\.)*)"`),
	regexp.MustCompile(`i18n\.In\([^,()]+,\s*"((?:[^"\\]|\\.)*)"`),
	regexp.MustCompile(`\{\{(?:t|th|tf|thf) "((?:[^"\\]|\\.)*)"`),
	regexp.MustCompile(`\badd\("((?:[^"\\]|\\.)*)"`),                // forms.Compile
	regexp.MustCompile(`\bnum\("[^"]*", "((?:[^"\\]|\\.)*)"\)`),     // admin parseDefinition labels
	regexp.MustCompile(`(?m)^\s*"[a-z]+":\s+"((?:[^"\\]|\\.)*)",$`), // admin flashes
	regexp.MustCompile(`return "((?:[^"\\]|\\.)+)"\s*$`),            // forms.badChars (filtered below)
}

func TestCatalogueCoversSources(t *testing.T) {
	root := filepath.Join("..", "..")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "docs" || n == "node_modules" || n == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if (ext != ".go" && ext != ".html") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, re := range keyPatterns {
			if i == 5 && !strings.HasSuffix(path, filepath.Join("admin", "admin.go")) {
				continue
			}
			if i == 6 && !strings.HasSuffix(path, filepath.Join("forms", "validate.go")) {
				continue
			}
			for _, line := range strings.Split(string(src), "\n") {
				for _, m := range re.FindAllStringSubmatch(line, -1) {
					key, err := strconv.Unquote(`"` + m[1] + `"`)
					if err != nil {
						t.Errorf("%s: cannot unquote %q", path, m[1])
						continue
					}
					if i == 6 && !strings.HasPrefix(key, "this field") {
						continue
					}
					checked++
					if !Has(key) {
						t.Errorf("%s: no Polish entry for %q", path, key)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 200 {
		t.Fatalf("only %d keys found; did the call shapes change?", checked)
	}
	for _, k := range []string{"invalid email address"} { // looked up via err.Error()
		if !Has(k) {
			t.Errorf("no Polish entry for %q", k)
		}
	}
}

func TestParseAndFallback(t *testing.T) {
	for in, want := range map[string]Lang{"pl": PL, "pl-PL": PL, "pl_PL.UTF-8": PL, "EN": EN, "en-GB": EN} {
		if l, ok := Parse(in); !ok || l != want {
			t.Errorf("Parse(%q) = %q, %v", in, l, ok)
		}
	}
	if _, ok := Parse("de"); ok {
		t.Error("de accepted")
	}
	if In(PL, "no such message") != "no such message" {
		t.Error("missing entry must fall back to English")
	}
}
