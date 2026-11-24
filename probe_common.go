package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// bindToDeviceHook overrides SO_BINDTODEVICE in tests on Linux.
var bindToDeviceHook func(fd int, ifaceName string) error

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

// Prober queries external IP echo endpoints with multi-source fallback,
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
		return ProbeResult{}, errors.New("no " + family.String() + " probe endpoints configured")
	}

	key := probeKey{family: family, iface: ifaceName}

	p.mu.Lock()
	if !refresh && p.cacheTTL > 0 {
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
	if err := ctx.Err(); err != nil {
		p.mu.Unlock()
		return ProbeResult{}, err
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
			now := p.now()
			for k, e := range p.cache {
				if !now.Before(e.expiresAt) {
					delete(p.cache, k)
				}
			}
			p.cache[key] = cacheEntry{
				res:       res,
				expiresAt: now.Add(p.cacheTTL),
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

func (p *Prober) probesFor(family IPFamily) []string {
	if family == FamilyV6 {
		return p.v6Probes
	}
	return p.v4Probes
}

func parseProbeIP(raw []byte, family IPFamily) (string, error) {
	text := strings.TrimSpace(string(raw))
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return "", errors.New("invalid IP response")
	}
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
		return "", errors.New("unusable IP response")
	}
	if family == FamilyV4 && !addr.Is4() {
		return "", errors.New("expected IPv4")
	}
	if family == FamilyV6 && !addr.Is6() {
		return "", errors.New("expected IPv6")
	}
	return addr.String(), nil
}
