package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

type LogEntry struct {
	Identity string `json:"identity"`
	Device   string `json:"device"`
	Domain   string `json:"domain"`
	Level    int    `json:"level"`
	Time     string `json:"time"`
}

var logCh chan logRequest

type logRequest struct {
	cfg        *Config
	identity   string
	deviceName string
	domain     string
	level      int
}

func StartLogWorker() {
	logCh = make(chan logRequest, 1024)
	go func() {
		for req := range logCh {
			writeLog(req)
		}
	}()
}

func AppendLog(cfg *Config, identity, deviceName, domain string, level int) {
	select {
	case logCh <- logRequest{cfg, identity, deviceName, domain, level}:
	default:
		// Channel full, drop log entry to avoid blocking DNS responses
	}
}

func writeLog(req logRequest) {
	entry := LogEntry{
		Identity: req.identity,
		Device:   req.deviceName,
		Domain:   req.domain,
		Level:    req.level,
		Time:     time.Now().Format("2006-01-02 15:04:05"),
	}

	entryJSON, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	encrypted, err := aesEncrypt(json.RawMessage(entryJSON), req.cfg.Passphrase)
	if err != nil {
		log.Printf("Failed to encrypt log entry: %v", err)
		return
	}

	logPath := filepath.Join(req.cfg.StorageDir, sanitizeFilename(req.identity)+"-raw.json")

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	f.WriteString(encrypted + "\n")
}
