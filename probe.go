package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// IPFamily represents an IP protocol version (IPv4 or IPv6).
type IPFamily int

const (
	FamilyV4 IPFamily = 4
	FamilyV6 IPFamily = 6
)

func (f IPFamily) network() string {
	if f == FamilyV6 {
		return "tcp6"
	}
	return "tcp4"
}

func (f IPFamily) String() string {
	if f == FamilyV6 {
		return "ipv6"
	}
	return "ipv4"
}

// ProbeResult holds the output of an external public IP probe.
type ProbeResult struct {
	IP     string
	Probe  string
	Cached bool
}

// ExternalProber abstracts public IP probing for testability.
type ExternalProber interface {
	Probe(ctx context.Context, family IPFamily, ifaceName string, localIP net.IP, refresh bool) (ProbeResult, error)
}

type probeKey struct {
	family IPFamily
	iface  string
}

type cacheEntry struct {
	res       ProbeResult
	expiresAt time.Time
}

type inflightCall struct {
	done chan struct{}
	res  ProbeResult
	err  error
}

// Prober queries external HTTP(S) IP echo endpoints with multi-source fallback,
// in-memory TTL caching, and concurrent request coalescing.
type Prober struct {
	v4Probes []string
	v6Probes []string
	timeout  time.Duration
	cacheTTL time.Duration
	now      func() time.Time

	mu       sync.Mutex
	cache    map[probeKey]cacheEntry
	inflight map[probeKey]*inflightCall
}

// NewProber constructs a Prober with the provided probe endpoints and timings.
func NewProber(v4Probes, v6Probes []string, timeout, cacheTTL time.Duration) *Prober {
	return &Prober{
		v4Probes: append([]string(nil), v4Probes...),
		v6Probes: append([]string(nil), v6Probes...),
		timeout:  timeout,
		cacheTTL: cacheTTL,
		now:      time.Now,
		cache:    make(map[probeKey]cacheEntry),
		inflight: make(map[probeKey]*inflightCall),
	}
}

// Probe discovers the public IP for the requested protocol family and optional interface.
func (p *Prober) Probe(ctx context.Context, family IPFamily, ifaceName string, localIP net.IP, refresh bool) (ProbeResult, error) {
	probes := p.probesFor(family)
	if len(probes) == 0 {
		return ProbeResult{}, fmt.Errorf("no %s probe endpoints configured", family)
	}

	key := probeKey{family: family, iface: ifaceName}

	if !refresh {
		p.mu.Lock()
		if p.cacheTTL > 0 {
			if entry, ok := p.cache[key]; ok && p.now().Before(entry.expiresAt) {
				res := entry.res
				res.Cached = true
				p.mu.Unlock()
				return res, nil
			}
		}
		if call, ok := p.inflight[key]; ok {
			p.mu.Unlock()
			select {
			case <-call.done:
				return call.res, call.err
			case <-ctx.Done():
				return ProbeResult{}, ctx.Err()
			}
		}
		call := &inflightCall{done: make(chan struct{})}
		p.inflight[key] = call
		p.mu.Unlock()

		go func() {
			budget := p.timeout * time.Duration(len(probes))
			if budget < p.timeout {
				budget = p.timeout
			}
			probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
			defer cancel()

			res, err := p.probeAll(probeCtx, family, probes, ifaceName, localIP)

			p.mu.Lock()
			if err == nil && p.cacheTTL > 0 {
				p.cache[key] = cacheEntry{
					res:       res,
					expiresAt: p.now().Add(p.cacheTTL),
				}
			}
			call.res = res
			call.err = err
			delete(p.inflight, key)
			close(call.done)
			p.mu.Unlock()
		}()

		select {
		case <-call.done:
			return call.res, call.err
		case <-ctx.Done():
			return ProbeResult{}, ctx.Err()
		}
	}

	// Forced refresh path: bypass cache and overwrite cached value on success.
	res, err := p.probeAll(ctx, family, probes, ifaceName, localIP)
	if err == nil && p.cacheTTL > 0 {
		p.mu.Lock()
		p.cache[key] = cacheEntry{
			res:       res,
			expiresAt: p.now().Add(p.cacheTTL),
		}
		p.mu.Unlock()
	}
	return res, err
}

func (p *Prober) probesFor(family IPFamily) []string {
	if family == FamilyV6 {
		return p.v6Probes
	}
	return p.v4Probes
}

func (p *Prober) probeAll(ctx context.Context, family IPFamily, probes []string, ifaceName string, localIP net.IP) (ProbeResult, error) {
	dialer := &net.Dialer{
		Timeout: p.timeout,
	}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	if ctrl := makeDialerControl(ifaceName); ctrl != nil {
		dialer.Control = ctrl
	}

	netType := family.network()
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, netType, addr)
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   p.timeout,
		ResponseHeaderTimeout: p.timeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	var lastErr error
	for _, probeURL := range probes {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		ipStr, err := probeOne(ctx, client, family, probeURL)
		if err == nil {
			return ProbeResult{
				IP:     ipStr,
				Probe:  probeURL,
				Cached: false,
			}, nil
		}
		lastErr = fmt.Errorf("%s: %w", probeURL, err)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("all %s probes failed", family)
	}
	return ProbeResult{}, lastErr
}

func probeOne(ctx context.Context, client *http.Client, family IPFamily, probeURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ippeek/1.0")
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}

	text := strings.TrimSpace(string(raw))
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return "", fmt.Errorf("invalid IP response %q", text)
	}
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
		return "", fmt.Errorf("unusable IP response %q", text)
	}
	if family == FamilyV4 && !addr.Is4() {
		return "", fmt.Errorf("expected IPv4, got %q", text)
	}
	if family == FamilyV6 && !addr.Is6() {
		return "", fmt.Errorf("expected IPv6, got %q", text)
	}

	return addr.String(), nil
}
