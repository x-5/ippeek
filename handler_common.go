package main

import (
	"crypto/subtle"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultReadHeaderTimeout  = 2 * time.Second
	defaultRequestTimeout     = 10 * time.Second
	defaultShutdownTimeout    = 5 * time.Second
	defaultMaxConcurrentConns = 128
	defaultMaxConnsPerIP      = 8
	defaultDropLogBurst       = 30
	defaultDropLogInterval    = 200 * time.Millisecond // 5 drop logs/sec sustained
	maxLogFieldLen            = 256
)

var allowedQueryKeys = map[string]struct{}{
	"token":   {},
	"v":       {},
	"format":  {},
	"iface":   {},
	"source":  {},
	"refresh": {},
}

// handlerCore holds shared state and security logic for both std and tiny servers.
type handlerCore struct {
	tokens            [][]byte
	resolver          *Resolver
	trustProxy        bool
	quietDrops        bool
	logOut            io.Writer
	logMu             sync.Mutex
	hostname          string
	now               func() time.Time
	readHeaderTimeout time.Duration
	requestTimeout    time.Duration
	shutdownTimeout   time.Duration
	maxConns          int
	maxConnsPerIP     int
	dropLimiter       *dropLogLimiter
}

func newHandlerCore(tokens []string, resolver *Resolver, trustProxy, quietDrops bool, logOut io.Writer) handlerCore {
	hostname, _ := os.Hostname()
	tokBytes := make([][]byte, 0, len(tokens))
	for _, t := range tokens {
		if t != "" {
			tokBytes = append(tokBytes, []byte(t))
		}
	}
	return handlerCore{
		tokens:            tokBytes,
		resolver:          resolver,
		trustProxy:        trustProxy,
		quietDrops:        quietDrops,
		logOut:            logOut,
		hostname:          hostname,
		now:               time.Now,
		readHeaderTimeout: defaultReadHeaderTimeout,
		requestTimeout:    defaultRequestTimeout,
		shutdownTimeout:   defaultShutdownTimeout,
		maxConns:          defaultMaxConcurrentConns,
		maxConnsPerIP:     defaultMaxConnsPerIP,
		dropLimiter:       newDropLogLimiter(defaultDropLogBurst, defaultDropLogInterval),
	}
}

// matchToken checks got against every configured token in constant time without short-circuiting.
func (c *handlerCore) matchToken(got string) bool {
	if len(got) == 0 || len(c.tokens) == 0 {
		return false
	}
	gotBytes := []byte(got)
	matched := 0
	for _, tok := range c.tokens {
		matched |= subtle.ConstantTimeCompare(gotBytes, tok)
	}
	return matched == 1
}

func (c *handlerCore) logAccess(status int, remote, method, path, rawQuery string) {
	c.logLine(
		strconv.Itoa(status) +
			" remote=" + sanitizeLogField(remote) +
			" method=" + sanitizeLogField(method) +
			" path=" + sanitizeLogField(path) +
			" query=" + sanitizeLogField(redactQuery(rawQuery)),
	)
}

func (c *handlerCore) logDrop(reason, remote, method, path, rawQuery string) {
	if c.quietDrops {
		return
	}
	allowed, suppressed := c.dropLimiter.Allow(c.now())
	if !allowed {
		return
	}
	msg := "444 drop (" + sanitizeLogField(reason) + ")" +
		" remote=" + sanitizeLogField(remote) +
		" method=" + sanitizeLogField(method) +
		" path=" + sanitizeLogField(path) +
		" query=" + sanitizeLogField(redactQuery(rawQuery))
	if suppressed > 0 {
		msg += " suppressed=" + strconv.FormatUint(suppressed, 10)
	}
	c.logLine(msg)
}

func (c *handlerCore) logLine(msg string) {
	if c.logOut == nil {
		return
	}
	line := "[ippeek] " + c.now().UTC().Format(time.RFC3339) + " " + msg + "\n"
	c.logMu.Lock()
	_, _ = io.WriteString(c.logOut, line)
	c.logMu.Unlock()
}

func parseStrictQuery(raw string) (map[string]string, bool) {
	out := make(map[string]string, 6)
	if raw == "" {
		return out, true
	}
	for raw != "" {
		var part string
		if idx := strings.IndexByte(raw, '&'); idx >= 0 {
			part = raw[:idx]
			raw = raw[idx+1:]
		} else {
			part = raw
			raw = ""
		}
		if part == "" || strings.ContainsRune(part, ';') {
			return nil, false
		}
		rawKey, rawVal, _ := strings.Cut(part, "=")
		key, ok := percentDecode(rawKey)
		if !ok {
			return nil, false
		}
		if _, allowed := allowedQueryKeys[key]; !allowed {
			return nil, false
		}
		if _, dup := out[key]; dup {
			return nil, false
		}
		val, ok := percentDecode(rawVal)
		if !ok {
			return nil, false
		}
		out[key] = val
	}
	return out, true
}

func percentDecode(s string) (string, bool) {
	if !strings.ContainsAny(s, "%+") {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteByte(' ')
		case '%':
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			b.WriteByte((hi << 4) | lo)
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

func percentDecodeBestEffort(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteByte(' ')
		case '%':
			if i+2 < len(s) {
				if hi, ok1 := unhex(s[i+1]); ok1 {
					if lo, ok2 := unhex(s[i+2]); ok2 {
						b.WriteByte((hi << 4) | lo)
						i += 2
						continue
					}
				}
			}
			b.WriteByte('%')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func parseValidParams(q map[string]string) (ResolveOptions, string, bool) {
	ver := q["v"]
	switch ver {
	case "", "all":
		ver = "all"
	case "4", "6":
	default:
		return ResolveOptions{}, "", false
	}

	format := q["format"]
	switch format {
	case "":
		if ver == "4" || ver == "6" {
			format = "text"
		} else {
			format = "json"
		}
	case "text", "json":
	default:
		return ResolveOptions{}, "", false
	}

	var source SourceMode
	switch q["source"] {
	case "", "auto":
		source = SourceAuto
	case "local":
		source = SourceLocal
	case "external":
		source = SourceExternal
	default:
		return ResolveOptions{}, "", false
	}

	refresh := false
	switch q["refresh"] {
	case "", "0", "false":
		refresh = false
	case "1", "true":
		refresh = true
	default:
		return ResolveOptions{}, "", false
	}

	iface := q["iface"]
	if len(iface) > 64 || !isValidIfaceName(iface) {
		return ResolveOptions{}, "", false
	}

	return ResolveOptions{
		Version: ver,
		Iface:   iface,
		Source:  source,
		Refresh: refresh,
	}, format, true
}

func isValidIfaceName(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func formatTextResult(ver string, res ResolveOutput) (int, string, string) {
	switch ver {
	case "4":
		if res.IPv4 == nil || res.IPv4.IP == "" {
			msg := "no ipv4 address available"
			if res.IPv4 != nil && res.IPv4.Error != "" {
				msg = res.IPv4.Error
			}
			return 503, "Service Unavailable", msg
		}
		return 200, "OK", res.IPv4.IP

	case "6":
		if res.IPv6 == nil || res.IPv6.IP == "" {
			msg := "no ipv6 address available"
			if res.IPv6 != nil && res.IPv6.Error != "" {
				msg = res.IPv6.Error
			}
			return 503, "Service Unavailable", msg
		}
		return 200, "OK", res.IPv6.IP

	default:
		var lines []string
		if res.IPv4 != nil && res.IPv4.IP != "" {
			lines = append(lines, "ipv4: "+res.IPv4.IP)
		}
		if res.IPv6 != nil && res.IPv6.IP != "" {
			lines = append(lines, "ipv6: "+res.IPv6.IP)
		}
		if len(lines) == 0 {
			return 503, "Service Unavailable", "no ip address available"
		}
		return 200, "OK", strings.Join(lines, "\n")
	}
}

// redactQuery masks any token parameter value, including percent-encoded keys like %74oken=SECRET.
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(raw))
	start := 0
	for start <= len(raw) {
		end := start
		for end < len(raw) && raw[end] != '&' && raw[end] != ';' {
			end++
		}
		part := raw[start:end]
		k, _, hasEq := strings.Cut(part, "=")
		decodedKey := percentDecodeBestEffort(k)
		if hasEq && strings.EqualFold(decodedKey, "token") {
			out.WriteString("token=***")
		} else {
			out.WriteString(part)
		}
		if end < len(raw) {
			out.WriteByte(raw[end])
			start = end + 1
		} else {
			break
		}
	}
	return out.String()
}

// sanitizeLogField strips/replaces ASCII control characters (< 0x20 and 0x7f) to prevent log injection.
func sanitizeLogField(s string) string {
	if s == "" {
		return ""
	}
	truncated := false
	if len(s) > maxLogFieldLen {
		s = s[:maxLogFieldLen]
		truncated = true
	}
	needsClean := false
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			needsClean = true
			break
		}
	}
	if !needsClean {
		if truncated {
			return s + "..."
		}
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteByte(c)
		}
	}
	if truncated {
		b.WriteString("...")
	}
	return b.String()
}

func peerIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	raw := addr.String()
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return host
	}
	return raw
}

func extractClientIP(remoteAddr, xff, xri string, trustProxy bool) string {
	if trustProxy {
		if xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if addr, err := netip.ParseAddr(first); err == nil {
				return addr.String()
			}
		}
		if xri != "" {
			if addr, err := netip.ParseAddr(xri); err == nil {
				return addr.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

// ipConnLimiter enforces a per-client-IP concurrent connection limit.
type ipConnLimiter struct {
	mu     sync.Mutex
	max    int
	counts map[string]int
}

func newIPConnLimiter(maxPerIP int) *ipConnLimiter {
	if maxPerIP <= 0 {
		maxPerIP = defaultMaxConnsPerIP
	}
	return &ipConnLimiter{
		max:    maxPerIP,
		counts: make(map[string]int),
	}
}

func (l *ipConnLimiter) Acquire(ip string) bool {
	if l == nil || l.max <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] >= l.max {
		return false
	}
	l.counts[ip]++
	return true
}

func (l *ipConnLimiter) Release(ip string) {
	if l == nil || l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.counts[ip]; n <= 1 {
		delete(l.counts, ip)
	} else {
		l.counts[ip] = n - 1
	}
}

type limitedListener struct {
	net.Listener
	sem    chan struct{}
	perIP  *ipConnLimiter
	onDrop func(reason, ip string)
}

func newLimitedListener(ln net.Listener, maxGlobal, maxPerIP int, onDrop func(reason, ip string)) net.Listener {
	if maxGlobal <= 0 {
		maxGlobal = defaultMaxConcurrentConns
	}
	if maxPerIP <= 0 {
		maxPerIP = defaultMaxConnsPerIP
	}
	return &limitedListener{
		Listener: ln,
		sem:      make(chan struct{}, maxGlobal),
		perIP:    newIPConnLimiter(maxPerIP),
		onDrop:   onDrop,
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := peerIP(c.RemoteAddr())
		if !l.perIP.Acquire(ip) {
			_ = c.Close()
			if l.onDrop != nil {
				l.onDrop("ip_conn_limit", ip)
			}
			continue
		}
		select {
		case l.sem <- struct{}{}:
			return &trackedConn{
				Conn: c,
				release: func() {
					<-l.sem
					l.perIP.Release(ip)
				},
			}, nil
		default:
			l.perIP.Release(ip)
			_ = c.Close()
			if l.onDrop != nil {
				l.onDrop("global_conn_limit", ip)
			}
		}
	}
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// dropLogLimiter is a lightweight token-bucket rate limiter for 444 drop log lines.
type dropLogLimiter struct {
	mu         sync.Mutex
	burst      int
	interval   time.Duration
	tokens     int
	lastRefill time.Time
	suppressed uint64
}

func newDropLogLimiter(burst int, interval time.Duration) *dropLogLimiter {
	if burst <= 0 {
		burst = defaultDropLogBurst
	}
	if interval <= 0 {
		interval = defaultDropLogInterval
	}
	return &dropLogLimiter{
		burst:    burst,
		interval: interval,
		tokens:   burst,
	}
}

func (l *dropLogLimiter) Allow(now time.Time) (bool, uint64) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastRefill.IsZero() {
		l.lastRefill = now
	} else if elapsed := now.Sub(l.lastRefill); elapsed > 0 {
		if elapsed >= time.Duration(l.burst)*l.interval {
			l.tokens = l.burst
			l.lastRefill = now
		} else if elapsed >= l.interval {
			add := int(elapsed / l.interval)
			l.tokens += add
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.lastRefill = l.lastRefill.Add(time.Duration(add) * l.interval)
		}
	}

	if l.tokens > 0 {
		l.tokens--
		sup := l.suppressed
		l.suppressed = 0
		return true, sup
	}
	l.suppressed++
	return false, 0
}
