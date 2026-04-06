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

func AppendLog(cfg *Config, identity, deviceName, domain string, level int) {
	entry := LogEntry{
		Identity: identity,
		Device:   deviceName,
		Domain:   domain,
		Level:    level,
		Time:     time.Now().Format("2006-01-02 15:04:05"),
	}

	entryJSON, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	encrypted, err := aesEncrypt(json.RawMessage(entryJSON), cfg.Passphrase)
	if err != nil {
		log.Printf("Failed to encrypt log entry: %v", err)
		return
	}

	logPath := filepath.Join(cfg.StorageDir, sanitizeFilename(identity)+"-raw.json")

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	f.WriteString(encrypted + "\n")
}
