package config

import (
	"strings"
	"testing"
)

func TestJevProviderDefaults(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Jev.Provider != "openrouter" || c.Jev.Enabled() {
		t.Fatalf("default must be openrouter and off without a key: %+v", c.Jev)
	}

	// basal needs no key and points at a local basal-serve by default.
	t.Setenv("JEV_PROVIDER", "basal")
	t.Setenv("OPENROUTER_API_KEY", "sk-or-not-for-basal")
	c, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	j := c.Jev
	if !j.Enabled() || !j.SelfHosted() || !j.LocalURL() || j.Model != "Remek/basal-omni-1.0-ultra" || j.URL != "http://127.0.0.1:8000/v1/systemone" {
		t.Fatalf("basal defaults: %+v", j)
	}
	if j.APIKey != "" {
		t.Fatal("the OpenRouter key must never be sent to a basal endpoint")
	}
}

func TestJevURLMustNotBePlaintextOffHost(t *testing.T) {
	t.Setenv("JEV_PROVIDER", "basal")
	t.Setenv("JEV_URL", "http://10.0.0.5:8000/v1/systemone")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "JEV_URL must use https") {
		t.Fatalf("plaintext to another host accepted: %v", err)
	}
	t.Setenv("JEV_URL", "https://gpu.internal.example/v1/systemone")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Jev.LocalURL() {
		t.Fatal("remote URL reported as local")
	}
}

func TestJevProviderValidated(t *testing.T) {
	t.Setenv("JEV_PROVIDER", "openai")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "JEV_PROVIDER") {
		t.Fatalf("unknown provider accepted: %v", err)
	}
}
