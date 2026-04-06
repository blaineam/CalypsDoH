package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DomainCodeAllowed       = 0
	DomainCodeAllowedDomain = 1
	DomainCodeAnnoyance     = 2
	DomainCodeBlocked       = 3
	DomainCodeAlarming      = 4
)

type Server struct {
	config    *Config
	blocklist *Blocklist
}

func (s *Server) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// Parse identity and device from URL path
	identity, deviceName := s.parseIdentityFromPath(r)

	// Validate identity
	if len(s.config.AllowedIdentities) > 0 && !containsStr(s.config.AllowedIdentities, identity) {
		http.Error(w, "Invalid Identifier passed to request", http.StatusForbidden)
		return
	}

	// Handle client config downloads
	if dl := r.URL.Query().Get("dl"); dl != "" {
		s.handleDownload(w, r, identity, deviceName, dl)
		return
	}

	// Get DNS query bytes
	dnsQuery, err := s.extractDNSQuery(r)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Parse DNS message to extract domain
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsQuery); err != nil {
		// Can't parse - just forward upstream
		s.proxyUpstream(w, dnsQuery)
		return
	}

	if len(msg.Question) == 0 {
		s.proxyUpstream(w, dnsQuery)
		return
	}

	domain := strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	qtype := msg.Question[0].Qtype

	// Check hardcoded blocks
	for _, blocked := range hardcodedBlocks {
		if domain == blocked {
			s.writeBlockedResponse(w, msg)
			return
		}
	}

	// Check remaps
	if ip, ok := s.config.Remaps[domain]; ok {
		s.writeRemappedResponse(w, msg, domain, ip, qtype)
		return
	}

	// Check blocklists
	domainLevel := s.checkBlocks(domain)
	if domainLevel >= s.config.BlockLevel {
		s.writeBlockedResponse(w, msg)
	} else {
		s.proxyUpstream(w, dnsQuery)
	}

	// Log asynchronously
	if s.config.EnableStats && s.config.Passphrase != "" {
		go AppendLog(s.config, identity, deviceName, domain, domainLevel)
	}
}

func (s *Server) parseIdentityFromPath(r *http.Request) (string, string) {
	path := strings.TrimPrefix(r.URL.Path, s.config.DLPrefix)
	path = strings.Trim(path, "/")
	parts := strings.SplitN(path, s.config.DLDelimiter, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 && parts[0] != "" {
		return parts[0], ""
	}
	return "", ""
}

func (s *Server) extractDNSQuery(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, fmt.Errorf("missing dns parameter")
		}
		// DoH uses base64url encoding (RFC 8484)
		return base64.RawURLEncoding.DecodeString(dnsParam)
	}

	// POST: raw binary body
	body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return body, nil
}

func (s *Server) checkBlocks(domain string) int {
	for _, fragment := range s.config.AllowedDomains {
		if strings.Contains(domain, fragment) {
			return DomainCodeAllowedDomain
		}
	}

	for _, fragment := range s.config.BlockedDomains {
		if strings.Contains(domain, fragment) {
			return DomainCodeBlocked
		}
	}

	if s.blocklist.IsAlarming(domain) {
		return DomainCodeAlarming
	}

	if s.blocklist.IsAnnoying(domain) {
		return DomainCodeAnnoyance
	}

	return DomainCodeAllowed
}

func (s *Server) proxyUpstream(w http.ResponseWriter, query []byte) {
	encoded := base64.RawURLEncoding.EncodeToString(query)

	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(s.config.DOHServers))))
	upstream := s.config.DOHServers[idx.Int64()]

	reqURL := upstream + "?dns=" + url.QueryEscape(encoded)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(body)
}

func (s *Server) writeBlockedResponse(w http.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	resp.RecursionDesired = true
	resp.RecursionAvailable = true

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func (s *Server) writeRemappedResponse(w http.ResponseWriter, req *dns.Msg, domain, ip string, qtype uint16) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionDesired = true
	resp.RecursionAvailable = true

	fqdn := dns.Fqdn(domain)
	switch qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   parseIP4(ip),
		})
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: parseIP6(ip),
		})
	}

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, identity, deviceName, dlType string) {
	host := sanitizeHost(r.Host)
	safeName := sanitizeFilename(deviceName)

	switch dlType {
	case "windows":
		GenerateWindowsInstaller(w, host, identity, deviceName, safeName, s.config)
	default:
		GenerateAppleProfile(w, host, identity, deviceName, safeName, s.config)
	}
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
