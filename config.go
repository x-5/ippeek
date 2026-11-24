package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListen       = ":8080"
	defaultCacheTTL     = 60 * time.Second
	defaultProbeTimeout = 3 * time.Second
	defaultV4Probes     = "http://4.ipw.cn,http://ip.3322.net,http://api4.ipify.org,http://ipv4.icanhazip.com"
	defaultV6Probes     = "http://6.ipw.cn,http://api6.ipify.org,http://ipv6.icanhazip.com"
)

// Config holds runtime configuration for the IP API server.
type Config struct {
	Listen       string
	Token        string
	CacheTTL     time.Duration
	ProbeTimeout time.Duration
	V4Probes     []string
	V6Probes     []string
	TrustProxy   bool
}

// LoadConfig parses configuration from environment variables and CLI flags (CLI takes precedence).
func LoadConfig(args []string, stderr io.Writer) (Config, error) {
	fs := flag.NewFlagSet("ippeek", flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}

	envListen := envOrDefault("IPPEEK_LISTEN", defaultListen)
	envToken := os.Getenv("IPPEEK_TOKEN")
	envV4 := envOrDefault("IPPEEK_V4_PROBES", defaultV4Probes)
	envV6 := envOrDefault("IPPEEK_V6_PROBES", defaultV6Probes)

	envCacheTTL, err := envDurationOrDefault("IPPEEK_CACHE_TTL", defaultCacheTTL)
	if err != nil {
		return Config{}, err
	}
	envProbeTimeout, err := envDurationOrDefault("IPPEEK_PROBE_TIMEOUT", defaultProbeTimeout)
	if err != nil {
		return Config{}, err
	}
	envTrustProxy, err := envBoolOrDefault("IPPEEK_TRUST_PROXY", false)
	if err != nil {
		return Config{}, err
	}

	var (
		listen       = fs.String("listen", envListen, "HTTP listen address (env: IPPEEK_LISTEN)")
		token        = fs.String("token", envToken, "Required authentication token (env: IPPEEK_TOKEN)")
		cacheTTL     = fs.Duration("cache-ttl", envCacheTTL, "Public IP probe cache TTL, 0 disables cache (env: IPPEEK_CACHE_TTL)")
		probeTimeout = fs.Duration("probe-timeout", envProbeTimeout, "Timeout per external IP probe (env: IPPEEK_PROBE_TIMEOUT)")
		v4ProbesRaw  = fs.String("v4-probes", envV4, "Comma-separated IPv4 probe URLs (env: IPPEEK_V4_PROBES)")
		v6ProbesRaw  = fs.String("v6-probes", envV6, "Comma-separated IPv6 probe URLs (env: IPPEEK_V6_PROBES)")
		trustProxy   = fs.Bool("trust-proxy", envTrustProxy, "Trust X-Forwarded-For / X-Real-IP headers for client_ip (env: IPPEEK_TRUST_PROXY)")
	)

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Listen:       strings.TrimSpace(*listen),
		Token:        strings.TrimSpace(*token),
		CacheTTL:     *cacheTTL,
		ProbeTimeout: *probeTimeout,
		V4Probes:     splitCSV(*v4ProbesRaw),
		V6Probes:     splitCSV(*v6ProbesRaw),
		TrustProxy:   *trustProxy,
	}

	if cfg.Listen == "" {
		return Config{}, errors.New("listen address must not be empty")
	}
	if cfg.Token == "" {
		return Config{}, errors.New("token is required: set -token or IPPEEK_TOKEN")
	}
	if cfg.CacheTTL < 0 {
		return Config{}, errors.New("cache-ttl must be >= 0")
	}
	if cfg.ProbeTimeout <= 0 {
		return Config{}, errors.New("probe-timeout must be > 0")
	}

	return cfg, nil
}

func envOrDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envDurationOrDefault(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q: %w", key, v, err)
	}
	return d, nil
}

func envBoolOrDefault(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("invalid %s=%q: %w", key, v, err)
	}
	return b, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
