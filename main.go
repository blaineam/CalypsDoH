package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func main() {
	cfg := loadConfig()

	StartLogWorker()

	bl := NewBlocklist(cfg)
	bl.Start()

	srv := &Server{
		config:    cfg,
		blocklist: bl,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.HandleRequest)

	addr := cfg.ListenAddr
	log.Printf("CalypsDoH starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

type Config struct {
	ListenAddr        string
	Passphrase        string
	AllowedIdentities []string
	DOHServers        []string
	AlarmingURLs      []string
	AnnoyingURLs      []string
	AllowedDomains    []string
	BlockedDomains    []string
	Remaps            map[string]string
	BlockLevel        int
	EnableStats       bool
	DLPrefix          string
	DLDelimiter       string
	StorageDir        string
}

var defaultDOHServers = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
}

var defaultAnnoyingURLs = []string{
	"https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
}

var defaultAlarmingURLs = []string{
	"https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
	"https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
}

var hardcodedBlocks = []string{
	"mask.icloud.com",
	"mask-h2.icloud.com",
}

func loadConfig() *Config {
	cfg := &Config{
		ListenAddr:  envOrDefault("LISTEN_ADDR", ":8053"),
		Passphrase:  os.Getenv("ENCRYPTION_PASSPHRASE_FOR_LOGS"),
		BlockLevel:  3,
		EnableStats: true,
		DLPrefix:    "/",
		DLDelimiter: "/",
		StorageDir:  "Storage",
	}

	if ids := os.Getenv("ALLOWED_IDENTITIES"); ids != "" {
		cfg.AllowedIdentities = splitAndFilter(ids, ",")
	}

	if servers := os.Getenv("DOH_SERVERS"); servers != "" {
		cfg.DOHServers = splitAndFilter(servers, ",")
	} else {
		cfg.DOHServers = defaultDOHServers
	}

	if urls := os.Getenv("ANNOYING_URLS"); urls != "" {
		cfg.AnnoyingURLs = splitAndFilter(urls, ",")
	} else {
		cfg.AnnoyingURLs = defaultAnnoyingURLs
	}

	if urls := os.Getenv("ALARMING_URLS"); urls != "" {
		cfg.AlarmingURLs = splitAndFilter(urls, ",")
	} else {
		cfg.AlarmingURLs = defaultAlarmingURLs
	}

	if domains := os.Getenv("ALLOWED_DOMAINS"); domains != "" {
		cfg.AllowedDomains = splitAndFilter(domains, ",")
	}

	if domains := os.Getenv("BLOCKED_DOMAINS"); domains != "" {
		cfg.BlockedDomains = splitAndFilter(domains, ",")
	}

	cfg.Remaps = make(map[string]string)
	if remaps := os.Getenv("REMAPS"); remaps != "" {
		for _, pair := range splitAndFilter(remaps, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				cfg.Remaps[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if lvl := os.Getenv("BLOCK_LEVEL"); lvl != "" {
		if n, err := strconv.Atoi(lvl); err == nil {
			cfg.BlockLevel = n
		}
	}

	if os.Getenv("ENABLE_STATS") == "false" {
		cfg.EnableStats = false
	}

	if p := os.Getenv("DL_PREFIX"); p != "" {
		cfg.DLPrefix = p
	}
	if d := os.Getenv("DL_DELIMITER"); d != "" {
		cfg.DLDelimiter = d
	}
	if s := os.Getenv("STORAGE_DIR"); s != "" {
		cfg.StorageDir = s
	}

	return cfg
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitAndFilter(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
