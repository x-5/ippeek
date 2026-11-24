package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPFamily represents IPv4 or IPv6.
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

func (f IPFamily) label() string {
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

// ExternalProber abstracts external public IP probing.
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

// Prober performs minimal raw-TCP HTTP/1.1 IP probing without net/http or crypto/tls.
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

// NewProber constructs a Prober.
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
		return ProbeResult{}, errors.New("no " + family.label() + " probe endpoints configured")
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

	var lastErr error
	for _, probeURL := range probes {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		ipStr, err := probeHTTP(ctx, dialer, family, probeURL, p.timeout, 0)
		if err == nil {
			return ProbeResult{
				IP:     ipStr,
				Probe:  probeURL,
				Cached: false,
			}, nil
		}
		lastErr = errors.New(probeURL + ": " + err.Error())
	}

	if lastErr == nil {
		lastErr = errors.New("all " + family.label() + " probes failed")
	}
	return ProbeResult{}, lastErr
}

func parseHTTPURL(raw string) (hostHeader, dialAddr, reqPath string, err error) {
	if strings.HasPrefix(raw, "https://") {
		return "", "", "", errors.New("https probes not supported in go-tiny build")
	}
	rest, ok := strings.CutPrefix(raw, "http://")
	if !ok || rest == "" {
		return "", "", "", errors.New("probe URL must start with http://")
	}

	var hostPort string
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		hostPort = rest[:idx]
		reqPath = rest[idx:]
	} else {
		hostPort = rest
		reqPath = "/"
	}
	if hostPort == "" {
		return "", "", "", errors.New("empty host in probe URL")
	}
	hostHeader = hostPort
	if _, _, splitErr := net.SplitHostPort(hostPort); splitErr == nil {
		dialAddr = hostPort
	} else {
		// Handle bracketed IPv6 literal without port or bare hostname.
		h := strings.TrimPrefix(strings.TrimSuffix(hostPort, "]"), "[")
		dialAddr = net.JoinHostPort(h, "80")
	}
	return hostHeader, dialAddr, reqPath, nil
}

func probeHTTP(ctx context.Context, dialer *net.Dialer, family IPFamily, rawURL string, timeout time.Duration, depth int) (string, error) {
	if depth > 3 {
		return "", errors.New("too many redirects")
	}
	hostHeader, dialAddr, reqPath, err := parseHTTPURL(rawURL)
	if err != nil {
		return "", err
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(reqCtx, family.network(), dialAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if dl, ok := reqCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	var req strings.Builder
	req.Grow(128)
	req.WriteString("GET ")
	req.WriteString(reqPath)
	req.WriteString(" HTTP/1.1\r\nHost: ")
	req.WriteString(hostHeader)
	req.WriteString("\r\nUser-Agent: ip-api/1.0\r\nAccept: text/plain\r\nConnection: close\r\n\r\n")

	if _, err := io.WriteString(conn, req.String()); err != nil {
		return "", err
	}

	br := bufio.NewReaderSize(conn, 1024)
	statusLine, err := readHeaderLine(br, 512)
	if err != nil {
		return "", err
	}

	// Expected: HTTP/1.x STATUS ...
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return "", errors.New("invalid HTTP status line")
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", errors.New("invalid HTTP status code")
	}

	var chunked bool
	var location string
	for i := 0; i < 64; i++ {
		line, err := readHeaderLine(br, 1024)
		if err != nil {
			return "", err
		}
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(v), "chunked") {
				chunked = true
			}
		case "location":
			location = v
		}
	}

	if (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308) && location != "" {
		return probeHTTP(ctx, dialer, family, location, timeout, depth+1)
	}
	if statusCode != 200 {
		return "", errors.New("unexpected HTTP status " + strconv.Itoa(statusCode))
	}

	var rawBody []byte
	if chunked {
		rawBody, err = readChunkedLimited(br, 128)
	} else {
		rawBody, err = io.ReadAll(io.LimitReader(br, 128))
	}
	if err != nil {
		return "", err
	}

	text := strings.TrimSpace(string(rawBody))
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

func readHeaderLine(br *bufio.Reader, maxLen int) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLen {
		return "", errors.New("header line too long")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func readChunkedLimited(br *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for len(out) < limit {
		sizeLine, err := readHeaderLine(br, 64)
		if err != nil {
			return nil, err
		}
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || n < 0 {
			return nil, errors.New("invalid chunk size")
		}
		if n == 0 {
			break
		}
		need := int(n)
		if len(out)+need > limit {
			need = limit - len(out)
		}
		buf := make([]byte, need)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		out = append(out, buf...)
		if int64(need) < n {
			break
		}
		// Consume trailing CRLF after chunk payload.
		if _, err := readHeaderLine(br, 16); err != nil {
			return nil, err
		}
	}
	return out, nil
}
