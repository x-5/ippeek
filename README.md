# ippeek

**English** | [简体中文](README.zh-CN.md)

An ultra-minimal, zero-dependency Go IP query API server featuring specific network interface binding, smart public IPv4/IPv6 resolution, plain-text/JSON dual output formats, and **444 connection-level 0-byte drop** for all non-conforming requests.

## Architecture Overview

```text
Client ──GET /ip?token=...──▶ Strict Validation (path / method / query allowlist / constant-time token)
                                │
                  Invalid ──────┴──────▶ 444 Connection Drop (0 bytes, immediate TCP close)
                                │
                    Valid ──────▼
                           Smart Resolver
                           ├─ source=local    → Read interface IP directly (including private IPs)
                           ├─ source=auto     → Prefer public IP on interface (skip RFC1918/CGNAT/ULA)
                           │                    Fall back to external probes (TTL cache + singleflight)
                           └─ source=external → Force external probe (supports outbound iface binding)
                                │
                                ▼
                  format=text (raw IP) / format=json (full metadata)
```

### Branches & Release Variants

| Variant | Branch | Description | Size (`linux/amd64`) |
| :--- | :--- | :--- | :---: |
| **`std`** (Standard) | `master` | Go standard library `net/http`; supports both `http://` and `https://` probes | ~5.6 MB |
| **`tiny`** (Minimal) | `go-tiny` | Drops `net/http` and `reflect`; raw `net` HTTP/1.1 & JSON (`http://` probes only) | ~1.9 MB |
| **`tiny-upx`** (Compressed) | `go-tiny` | `tiny` build packed with UPX (`--best --lzma`), ideal for routers/embedded devices | **~658 KB** |

## Usage

### 1. One-Click systemd Deployment / Update / Check / Uninstall (Linux)

```bash
# One-click install (defaults to tiny-upx; auto-generates a random token if --token is omitted)
curl -fsSL https://raw.githubusercontent.com/x-5/ippeek/master/install.sh | \
  sudo bash -s -- install --token YOUR_SECRET --listen :8080

# Install a specific variant (tiny-upx / tiny / std)
sudo bash install.sh install --variant std --token YOUR_SECRET

# One-click update (preserves /etc/ippeek/ippeek.env)
sudo bash install.sh update

# One-click health check (service status + 444 drop & auth loopback self-test + logs)
sudo bash install.sh check

# One-click uninstall (add --keep-config to preserve config files)
sudo bash install.sh uninstall
```

### 2. Direct Execution / Environment Variables

CLI flags take precedence over environment variables (`-token` / `IPPEEK_TOKEN` is required):

```bash
IPPEEK_TOKEN=YOUR_SECRET ./ippeek -listen :8080
```

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `-listen` | `IPPEEK_LISTEN` | `:8080` | Listen address |
| `-token` | `IPPEEK_TOKEN` | **Required** | Authentication token |
| `-cache-ttl` | `IPPEEK_CACHE_TTL` | `60s` | External probe cache TTL (`0` disables caching) |
| `-probe-timeout` | `IPPEEK_PROBE_TIMEOUT` | `3s` | Timeout per external probe |
| `-v4-probes` | `IPPEEK_V4_PROBES` | `4.ipw.cn,ip.3322.net,api4.ipify.org,ipv4.icanhazip.com` | IPv4 probe endpoints |
| `-v6-probes` | `IPPEEK_V6_PROBES` | `6.ipw.cn,api6.ipify.org,ipv6.icanhazip.com` | IPv6 probe endpoints |
| `-trust-proxy` | `IPPEEK_TRUST_PROXY` | `false` | Trust reverse-proxy headers for `client_ip` |

### 3. API Endpoint (Single Entry: `GET /ip`)

Query parameter allowlist: `token` (required), `v` (`4` / `6` / `all`), `format` (`text` / `json`), `iface` (network interface name), `source` (`auto` / `local` / `external`), `refresh` (`1` / `true`). Any non-conforming request triggers an immediate 444 connection drop.

```bash
# Plain-text public IPv4 / IPv6 (v=4/6 defaults to text with no trailing newline)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=6"

# Specific network interface (smart public IP / local-only IP)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0&source=local"

# Full JSON summary (v=all defaults to json)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET"

# Force refresh probe cache
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&refresh=1"
```

### 4. Building & Testing with Docker

```bash
make test           # Run all unit tests and 444 TCP drop tests
make build-all      # Cross-compile binaries for all platforms into dist/
make docker-image   # Build minimal FROM scratch Docker image
```
