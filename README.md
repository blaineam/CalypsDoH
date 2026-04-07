# CalypsDoH

An encrypted DNS-over-HTTPS proxy with ad and tracker blocking, written in Go.

## Features

- **DNS-over-HTTPS proxying** -- accepts standard DoH GET and POST requests, forwards to upstream resolvers (Google DNS, Cloudflare, or custom)
- **Blocklist management** -- pulls community blocklists on a schedule and blocks matching domains with `0.0.0.0` / `::` responses
- **Configurable block levels** -- separate "annoying" (ads, tracking, malware) and "alarming" (adult, drugs, gambling) tiers
- **Domain remapping** -- rewrite specific domains to alternate IPs
- **Encrypted logging** -- request logs are AES-encrypted at rest
- **Apple config profile generation** -- serves `.mobileconfig` profiles so iOS/macOS devices can use your proxy directly

## Building

```bash
go build -o calypsdoh .
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8053` | Address and port to listen on |
| `ENCRYPTION_PASSPHRASE_FOR_LOGS` | *(empty)* | AES passphrase for encrypted log files |
| `ALLOWED_IDENTITIES` | *(empty)* | Comma-separated identity tokens for profile downloads |
| `DOH_SERVERS` | Google, Cloudflare | Comma-separated upstream DoH server URLs |
| `ANNOYING_URLS` | Blocklist Project lists | Comma-separated blocklist URLs (ads, tracking, malware) |
| `ALARMING_URLS` | Blocklist Project lists | Comma-separated blocklist URLs (adult, drugs, gambling) |
| `ALLOWED_DOMAINS` | *(empty)* | Comma-separated domains to always allow |
| `BLOCKED_DOMAINS` | *(empty)* | Comma-separated domains to always block |
| `REMAPS` | *(empty)* | Comma-separated `domain=ip` pairs for domain remapping |
| `BLOCK_LEVEL` | `3` | Block level: 1 = off, 2 = annoying only, 3 = annoying + alarming |
| `ENABLE_STATS` | `true` | Enable request statistics logging |
| `DL_PREFIX` | `/` | URL prefix for profile download paths |
| `DL_DELIMITER` | `/` | Delimiter between identity and device name in download URLs |
| `STORAGE_DIR` | `Storage` | Directory for blocklist cache and log files |

## Running as a Daemon

Use the included `install-daemon.sh` to install CalypsDoH as a background service:

```bash
# Install and start
./install-daemon.sh

# Check status
./install-daemon.sh status

# Stop and remove
./install-daemon.sh uninstall
```

- **macOS**: installs a LaunchAgent at `~/Library/LaunchAgents/com.calypsdoh.daemon.plist`
- **Linux**: installs a systemd user service at `~/.config/systemd/user/calypsdoh.service`

The script will build the binary automatically if it does not already exist.

## Security Notes

The Go implementation (April 2026 audit) includes:

- HTTP server timeouts (read, write, idle, header) to prevent slowloris and resource exhaustion
- Maximum header size limits
- Input validation on DNS wire-format payloads
- Encrypted log storage using AES

## License

This project is released into the public domain under the [Unlicense](https://unlicense.org).
