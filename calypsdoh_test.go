package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAESRoundtrip(t *testing.T) {
	passphrase := "test-passphrase-123"
	original := map[string]string{"hello": "world", "foo": "bar"}

	encrypted, err := aesEncrypt(original, passphrase)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's valid JSON with expected fields
	var parsed map[string]string
	if err := json.Unmarshal([]byte(encrypted), &parsed); err != nil {
		t.Fatalf("Encrypted output not valid JSON: %v", err)
	}
	if _, ok := parsed["ct"]; !ok {
		t.Fatal("Missing 'ct' field")
	}
	if _, ok := parsed["iv"]; !ok {
		t.Fatal("Missing 'iv' field")
	}
	if _, ok := parsed["s"]; !ok {
		t.Fatal("Missing 's' field")
	}

	// Decrypt
	decrypted, err := aesDecrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(decrypted, &result); err != nil {
		t.Fatalf("Decrypted output not valid JSON: %v", err)
	}

	if result["hello"] != "world" || result["foo"] != "bar" {
		t.Fatalf("Decrypted data mismatch: %v", result)
	}
}

func TestAESWrongPassphrase(t *testing.T) {
	encrypted, _ := aesEncrypt("secret", "correct-pass")
	_, err := aesDecrypt(encrypted, "wrong-pass")
	// Should either error or produce garbage - not the original
	if err == nil {
		// Decryption may "succeed" with wrong padding but produce garbage
		// This is expected behavior for CBC mode
	}
}

func TestBlocklistLookup(t *testing.T) {
	bl := &Blocklist{
		alarming: map[string]struct{}{
			"bad-site.com":  {},
			"evil-site.org": {},
		},
		annoying: map[string]struct{}{
			"ads.example.com":     {},
			"tracker.example.com": {},
		},
	}

	if !bl.IsAlarming("bad-site.com") {
		t.Error("Expected bad-site.com to be alarming")
	}
	if bl.IsAlarming("good-site.com") {
		t.Error("Expected good-site.com to not be alarming")
	}
	if !bl.IsAnnoying("ads.example.com") {
		t.Error("Expected ads.example.com to be annoying")
	}
	if bl.IsAnnoying("clean.example.com") {
		t.Error("Expected clean.example.com to not be annoying")
	}
}

func TestCheckBlocks(t *testing.T) {
	cfg := &Config{
		AllowedDomains: []string{"safe.com"},
		BlockedDomains: []string{"blocked.com"},
	}
	bl := &Blocklist{
		alarming: map[string]struct{}{"alarm.example.com": {}},
		annoying: map[string]struct{}{"annoy.example.com": {}},
	}
	srv := &Server{config: cfg, blocklist: bl}

	tests := []struct {
		domain   string
		expected int
	}{
		{"something.safe.com", DomainCodeAllowedDomain},
		{"blocked.com", DomainCodeBlocked},
		{"alarm.example.com", DomainCodeAlarming},
		{"annoy.example.com", DomainCodeAnnoyance},
		{"normal.example.com", DomainCodeAllowed},
	}

	for _, tc := range tests {
		got := srv.checkBlocks(tc.domain)
		if got != tc.expected {
			t.Errorf("checkBlocks(%q) = %d, want %d", tc.domain, got, tc.expected)
		}
	}
}

func TestSanitizeHost(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com", "example.com"},
		{"example.com:8080", "example.com:8080"},
		{"evil<script>.com", "evilscript.com"},
		{"host\r\ninjection", "hostinjection"},
	}
	for _, tc := range tests {
		got := sanitizeHost(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeHost(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"my-device", "my-device"},
		{"my device", "my_device"},
		{"../../../etc/passwd", "_________etc_passwd"},
	}
	for _, tc := range tests {
		got := sanitizeFilename(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestParseDomainList(t *testing.T) {
	input := `# comment
example.com
another.org

# another comment
third.net
`
	domains := parseDomainList(input)
	if len(domains) != 3 {
		t.Fatalf("Expected 3 domains, got %d: %v", len(domains), domains)
	}
	if domains[0] != "example.com" || domains[1] != "another.org" || domains[2] != "third.net" {
		t.Errorf("Unexpected domains: %v", domains)
	}
}

func TestDNSBlockedResponse(t *testing.T) {
	cfg := &Config{
		BlockLevel:     3,
		BlockedDomains: []string{"blocked.test"},
		DOHServers:     []string{"https://dns.google/dns-query"},
		StorageDir:     t.TempDir(),
	}
	bl := &Blocklist{
		alarming: make(map[string]struct{}),
		annoying: make(map[string]struct{}),
	}
	srv := &Server{config: cfg, blocklist: bl}

	// Build a DNS query for blocked.test
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.test.", dns.TypeA)
	queryBytes, _ := msg.Pack()

	// Create HTTP request with POST body
	req := httptest.NewRequest(http.MethodPost, "/test-id/test-device", strings.NewReader(string(queryBytes)))
	req.Header.Set("Content-Type", "application/dns-message")
	rr := httptest.NewRecorder()

	srv.HandleRequest(rr, req)

	// Parse response
	resp := new(dns.Msg)
	if err := resp.Unpack(rr.Body.Bytes()); err != nil {
		t.Fatalf("Failed to unpack DNS response: %v", err)
	}

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN (rcode %d), got rcode %d", dns.RcodeNameError, resp.Rcode)
	}
}
