# ippeek

**English** | [简体中文](README.zh-CN.md)

An ultra-minimal, zero-dependency Go IP query API server featuring strict network interface binding, smart public IPv4/IPv6 resolution, plain-text/JSON dual output formats, and **444 connection-level 0-byte drop** for all non-conforming requests.

## Architecture Overview

```text
Client ──GET /ip?token=...──▶ Strict Validation (path / method / query allowlist / constant-time multi-token)
                                │
                  Invalid ──────┴──────▶ 444 Connection Drop (0 bytes, immediate TCP close)
                                │
                    Valid ──────▼
                           Smart Resolver
                           ├─ source=local    → Read interface IP directly (including private IPs)
                           ├─ source=auto     → Prefer stable public IP on interface (skip RFC1918/CGNAT/ULA/deprecated)
                           │                    Fall back to external probes (TTL cache + singleflight)
                           └─ source=external → Force external probe (strict outbound iface binding)
                                │
                                ▼
                  format=text (raw IP) / format=json (full metadata)
```

### Build Editions & Release Variants

All editions are built from the single `master` branch via Go build tags:

| Variant | Build Command | Description | Size (`linux/amd64`) |
| :--- | :--- | :--- | :---: |
| **`std`** (Standard) | `go build .` | Go standard library `net/http`; supports both `http://` and `https://` probes | ~5.6 MB |
| **`tiny`** (Minimal) | `go build -tags tiny .` | Drops `net/http` and `reflect`; raw `net` HTTP/1.1 & JSON (`http://` probes only) | ~1.9 MB |
| **`tiny-upx`** (Compressed) | `go build -tags tiny .` + UPX | `tiny` build packed with UPX (`--best --lzma`), ideal for routers/embedded devices | **~658 KB** |

## Usage

### 1. One-Click systemd Deployment / Update / Check / Uninstall (Linux)

```bash
# One-click install (defaults to tiny-upx; auto-generates a random token if --token is omitted)
curl -fsSL https://raw.githubusercontent.com/x-5/ippeek/master/install.sh | \
  sudo bash -s -- install --token YOUR_SECRET --listen :8080

# Install with multi-token rotation, quiet 444 drop logs, or std variant
sudo bash install.sh install --variant std --token "NEW_SECRET,OLD_SECRET" --quiet-drops

# One-click update (preserves /etc/ippeek/ippeek.env)
sudo bash install.sh update

# One-click health check (binary -version, service status, 444/200 loopback self-test via curl -K -, logs)
sudo bash install.sh check

# One-click uninstall (add --keep-config to preserve config files)
sudo bash install.sh uninstall
```

### 2. Direct Execution / Environment Variables

CLI flags take precedence over environment variables (`-token` / `IPPEEK_TOKEN` is required unless `-version` is passed):

```bash
IPPEEK_TOKEN="NEW_SECRET,OLD_SECRET" ./ippeek -listen :8080 -quiet-drops
./ippeek -version
```

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `-listen` | `IPPEEK_LISTEN` | `:8080` | Listen address |
| `-token` | `IPPEEK_TOKEN` | **Required** | Authentication token(s), comma-separated for zero-downtime rotation |
| `-cache-ttl` | `IPPEEK_CACHE_TTL` | `60s` | External probe cache TTL (`0` disables caching) |
| `-probe-timeout` | `IPPEEK_PROBE_TIMEOUT` | `3s` | Timeout per external probe |
| `-v4-probes` | `IPPEEK_V4_PROBES` | `4.ipw.cn,ip.3322.net,api4.ipify.org,ipv4.icanhazip.com` | IPv4 probe endpoints |
| `-v6-probes` | `IPPEEK_V6_PROBES` | `6.ipw.cn,api6.ipify.org,ipv6.icanhazip.com` | IPv6 probe endpoints |
| `-trust-proxy` | `IPPEEK_TRUST_PROXY` | `false` | Trust reverse-proxy headers for `client_ip` |
| `-quiet-drops` | `IPPEEK_QUIET_DROPS` | `false` | Suppress 444 connection-drop log lines |
| `-version` | — | `false` | Print version and exit |

### 3. API Endpoint (Single Entry: `GET /ip`)

Query parameter allowlist: `token` (required), `v` (`4` / `6` / `all`), `format` (`text` / `json`), `iface` (network interface name), `source` (`auto` / `local` / `external`), `refresh` (`1` / `true`). Any non-conforming request triggers an immediate 444 connection drop.

```bash
# Plain-text public IPv4 / IPv6 (v=4/6 defaults to text with no trailing newline)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=6"

# Specific network interface (strict outbound binding / local-only IP)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0&source=local"

# Full JSON summary (v=all defaults to json)
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET"

# Force refresh probe cache
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&refresh=1"
```

### 4. Building & Testing with Docker

```bash
make test                         # Run unit and 444 tests for both std and -tags tiny
make build                        # Build std, tiny, and tiny-upx linux/amd64 binaries into dist/
make build-all                    # Cross-compile all 3 editions + checksums.txt into dist/
make docker-image                 # Build FROM scratch image (BUILD_TAGS=tiny; use BUILD_TAGS="" for std)
```
