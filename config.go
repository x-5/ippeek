package main

import (
	"errors"
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

// Config holds runtime configuration for the ultra-slim IP API server.
type Config struct {
	Listen       string
	Token        string
	CacheTTL     time.Duration
	ProbeTimeout time.Duration
	V4Probes     []string
	V6Probes     []string
	TrustProxy   bool
}

// LoadConfig parses configuration from environment variables and CLI arguments without flag/fmt/reflect.
func LoadConfig(args []string) (Config, error) {
	cfg := Config{
		Listen:       envOrDefault("IPPEEK_LISTEN", defaultListen),
		Token:        strings.TrimSpace(os.Getenv("IPPEEK_TOKEN")),
		CacheTTL:     defaultCacheTTL,
		ProbeTimeout: defaultProbeTimeout,
		V4Probes:     splitCSV(envOrDefault("IPPEEK_V4_PROBES", defaultV4Probes)),
		V6Probes:     splitCSV(envOrDefault("IPPEEK_V6_PROBES", defaultV6Probes)),
	}

	var err error
	if cfg.CacheTTL, err = envDurationOrDefault("IPPEEK_CACHE_TTL", defaultCacheTTL); err != nil {
		return Config{}, err
	}
	if cfg.ProbeTimeout, err = envDurationOrDefault("IPPEEK_PROBE_TIMEOUT", defaultProbeTimeout); err != nil {
		return Config{}, err
	}
	if cfg.TrustProxy, err = envBoolOrDefault("IPPEEK_TRUST_PROXY", false); err != nil {
		return Config{}, err
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			return Config{}, errors.New("unexpected positional argument: " + arg)
		}
		trimmed := strings.TrimLeft(arg, "-")
		name, val, hasEq := strings.Cut(trimmed, "=")

		nextVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", errors.New("missing value for flag -" + name)
			}
			i++
			return args[i], nil
		}

		switch name {
		case "h", "help":
			return Config{}, errors.New("usage: ippeek -token SECRET [-listen :8080] [-cache-ttl 60s] [-probe-timeout 3s] [-v4-probes ...] [-v6-probes ...] [-trust-proxy]")
		case "listen":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			cfg.Listen = strings.TrimSpace(v)
		case "token":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			cfg.Token = strings.TrimSpace(v)
		case "cache-ttl":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			d, err := time.ParseDuration(strings.TrimSpace(v))
			if err != nil {
				return Config{}, errors.New("invalid -cache-ttl: " + err.Error())
			}
			cfg.CacheTTL = d
		case "probe-timeout":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			d, err := time.ParseDuration(strings.TrimSpace(v))
			if err != nil {
				return Config{}, errors.New("invalid -probe-timeout: " + err.Error())
			}
			cfg.ProbeTimeout = d
		case "v4-probes":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			cfg.V4Probes = splitCSV(v)
		case "v6-probes":
			v, err := nextVal()
			if err != nil {
				return Config{}, err
			}
			cfg.V6Probes = splitCSV(v)
		case "trust-proxy":
			if hasEq {
				b, err := strconv.ParseBool(strings.TrimSpace(val))
				if err != nil {
					return Config{}, errors.New("invalid -trust-proxy: " + err.Error())
				}
				cfg.TrustProxy = b
			} else {
				cfg.TrustProxy = true
			}
		default:
			return Config{}, errors.New("unknown flag: -" + name)
		}
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
		return 0, errors.New("invalid " + key + ": " + err.Error())
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
		return false, errors.New("invalid " + key + ": " + err.Error())
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
