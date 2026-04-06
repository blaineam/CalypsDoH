package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Blocklist struct {
	config *Config

	alarmingMu sync.RWMutex
	alarming   map[string]struct{}

	annoyingMu sync.RWMutex
	annoying   map[string]struct{}
}

func NewBlocklist(cfg *Config) *Blocklist {
	return &Blocklist{
		config:   cfg,
		alarming: make(map[string]struct{}),
		annoying: make(map[string]struct{}),
	}
}

func (b *Blocklist) Start() {
	b.refresh()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			b.refresh()
		}
	}()
}

func (b *Blocklist) IsAlarming(domain string) bool {
	b.alarmingMu.RLock()
	defer b.alarmingMu.RUnlock()
	_, ok := b.alarming[domain]
	return ok
}

func (b *Blocklist) IsAnnoying(domain string) bool {
	b.annoyingMu.RLock()
	defer b.annoyingMu.RUnlock()
	_, ok := b.annoying[domain]
	return ok
}

func (b *Blocklist) refresh() {
	log.Println("Refreshing blocklists...")

	alarming := make(map[string]struct{})
	annoying := make(map[string]struct{})

	var wg sync.WaitGroup

	var alarmMu sync.Mutex
	for _, u := range b.config.AlarmingURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			domains := fetchBlocklist(url, filepath.Join(b.config.StorageDir, "ALARMING"))
			alarmMu.Lock()
			for _, d := range domains {
				alarming[d] = struct{}{}
			}
			alarmMu.Unlock()
		}(u)
	}

	var annoyMu sync.Mutex
	for _, u := range b.config.AnnoyingURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			domains := fetchBlocklist(url, filepath.Join(b.config.StorageDir, "ANNOYANCES"))
			annoyMu.Lock()
			for _, d := range domains {
				annoying[d] = struct{}{}
			}
			annoyMu.Unlock()
		}(u)
	}

	wg.Wait()

	b.alarmingMu.Lock()
	b.alarming = alarming
	b.alarmingMu.Unlock()

	b.annoyingMu.Lock()
	b.annoying = annoying
	b.annoyingMu.Unlock()

	log.Printf("Blocklists loaded: %d alarming, %d annoying domains", len(alarming), len(annoying))
}

func fetchBlocklist(url, cacheDir string) []string {
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		log.Printf("Failed to create cache dir %s: %v", cacheDir, err)
		return nil
	}

	filename := filepath.Base(url)
	cachePath := filepath.Join(cacheDir, filename)

	// Use cached file if fresh (< 24h)
	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < 24*time.Hour {
			return readDomainFile(cachePath)
		}
	}

	// Download fresh copy
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to download blocklist %s: %v", url, err)
		// Fall back to cache
		return readDomainFile(cachePath)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Blocklist %s returned status %d, using cache", url, resp.StatusCode)
		return readDomainFile(cachePath)
	}

	// Cap blocklist downloads at 50MB to prevent OOM
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		log.Printf("Failed to read blocklist %s: %v", url, err)
		return readDomainFile(cachePath)
	}

	if err := os.WriteFile(cachePath, body, 0640); err != nil {
		log.Printf("Failed to cache blocklist %s: %v", cachePath, err)
	}

	return parseDomainList(string(body))
}

func readDomainFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}

func parseDomainList(data string) []string {
	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}
