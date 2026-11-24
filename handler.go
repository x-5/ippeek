package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
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
	maxReqHeadersBytes = 4096
	maxReqHeaderLines  = 64
)

var allowedQueryKeys = map[string]struct{}{
	"token":   {},
	"v":       {},
	"format":  {},
	"iface":   {},
	"source":  {},
	"refresh": {},
}

// ServerHandler serves the single /ip endpoint over raw TCP connections
// and drops all non-conforming requests with 0 response bytes (Nginx 444 semantics).
type ServerHandler struct {
	token      []byte
	resolver   *Resolver
	trustProxy bool
	logOut     io.Writer
	logMu      sync.Mutex
	hostname   string
	now        func() time.Time
}

// NewServerHandler constructs a ServerHandler.
func NewServerHandler(token string, resolver *Resolver, trustProxy bool, logOut io.Writer) *ServerHandler {
	hostname, _ := os.Hostname()
	return &ServerHandler{
		token:      []byte(token),
		resolver:   resolver,
		trustProxy: trustProxy,
		logOut:     logOut,
		hostname:   hostname,
		now:        time.Now,
	}
}

// HandleConn processes a single TCP connection and closes it when done.
func (h *ServerHandler) HandleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}

	br := bufio.NewReaderSize(io.LimitReader(conn, maxReqHeadersBytes), 1024)
	reqLine, err := readHeaderLine(br, 1024)
	if err != nil {
		h.logDrop("malformed_request", remoteAddr, "", "", "")
		return
	}

	method, target, proto, ok := parseRequestLine(reqLine)
	if !ok {
		h.logDrop("malformed_request_line", remoteAddr, "", "", "")
		return
	}
	_ = proto

	var xff, xri string
	headersDone := false
	for i := 0; i < maxReqHeaderLines; i++ {
		line, err := readHeaderLine(br, 1024)
		if err != nil {
			h.logDrop("malformed_headers", remoteAddr, method, target, "")
			return
		}
		if line == "" {
			headersDone = true
			break
		}
		k, v, hasColon := strings.Cut(line, ":")
		if !hasColon {
			h.logDrop("malformed_header_line", remoteAddr, method, target, "")
			return
		}
		if h.trustProxy {
			lk := strings.ToLower(strings.TrimSpace(k))
			switch lk {
			case "x-forwarded-for":
				if xff == "" {
					xff = strings.TrimSpace(v)
				}
			case "x-real-ip":
				if xri == "" {
					xri = strings.TrimSpace(v)
				}
			}
		}
	}
	if !headersDone {
		h.logDrop("too_many_headers", remoteAddr, method, target, "")
		return
	}

	path, rawQuery, _ := strings.Cut(target, "?")
	clientIP := extractClientIP(remoteAddr, xff, xri, h.trustProxy)

	if path != "/ip" {
		h.logDrop("invalid_path", clientIP, method, path, rawQuery)
		return
	}
	if method != "GET" && method != "HEAD" {
		h.logDrop("invalid_method", clientIP, method, path, rawQuery)
		return
	}

	q, ok := parseStrictQuery(rawQuery)
	if !ok {
		h.logDrop("invalid_query", clientIP, method, path, rawQuery)
		return
	}

	gotToken := q["token"]
	if len(gotToken) == 0 || subtle.ConstantTimeCompare([]byte(gotToken), h.token) != 1 {
		h.logDrop("unauthorized", clientIP, method, path, rawQuery)
		return
	}

	opts, format, ok := parseValidParams(q)
	if !ok {
		h.logDrop("invalid_param_value", clientIP, method, path, rawQuery)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	res, err := h.resolver.Resolve(reqCtx, opts)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			h.writeError(conn, method, format, 404, "Not Found", err.Error(), clientIP, path, rawQuery)
			return
		}
		h.writeError(conn, method, format, 500, "Internal Server Error", err.Error(), clientIP, path, rawQuery)
		return
	}

	if format == "json" {
		payload := OverviewResponse{
			IPv4:       res.IPv4,
			IPv6:       res.IPv6,
			Interfaces: res.Interfaces,
			ClientIP:   clientIP,
			Hostname:   h.hostname,
			Timestamp:  h.now().UTC().Format(time.RFC3339),
		}
		body := marshalOverviewJSON(payload)
		h.writeResponse(conn, method, 200, "OK", "application/json; charset=utf-8", body, clientIP, path, rawQuery)
		return
	}

	h.writeTextResult(conn, method, opts.Version, res, clientIP, path, rawQuery)
}

func parseRequestLine(line string) (method, target, proto string, ok bool) {
	sp1 := strings.IndexByte(line, ' ')
	if sp1 <= 0 {
		return "", "", "", false
	}
	rest := line[sp1+1:]
	sp2 := strings.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return "", "", "", false
	}
	method = line[:sp1]
	target = rest[:sp2]
	proto = rest[sp2+1:]
	if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
		return "", "", "", false
	}
	return method, target, proto, true
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
	version := q["v"]
	switch version {
	case "", "all":
		version = "all"
	case "4", "6":
	default:
		return ResolveOptions{}, "", false
	}

	format := q["format"]
	switch format {
	case "":
		if version == "4" || version == "6" {
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
		Version: version,
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

func (h *ServerHandler) writeTextResult(conn net.Conn, method, version string, res ResolveOutput, clientIP, path, rawQuery string) {
	switch version {
	case "4":
		if res.IPv4 == nil || res.IPv4.IP == "" {
			msg := "no ipv4 address available"
			if res.IPv4 != nil && res.IPv4.Error != "" {
				msg = res.IPv4.Error
			}
			h.writeResponse(conn, method, 503, "Service Unavailable", "text/plain; charset=utf-8", []byte(msg), clientIP, path, rawQuery)
			return
		}
		h.writeResponse(conn, method, 200, "OK", "text/plain; charset=utf-8", []byte(res.IPv4.IP), clientIP, path, rawQuery)

	case "6":
		if res.IPv6 == nil || res.IPv6.IP == "" {
			msg := "no ipv6 address available"
			if res.IPv6 != nil && res.IPv6.Error != "" {
				msg = res.IPv6.Error
			}
			h.writeResponse(conn, method, 503, "Service Unavailable", "text/plain; charset=utf-8", []byte(msg), clientIP, path, rawQuery)
			return
		}
		h.writeResponse(conn, method, 200, "OK", "text/plain; charset=utf-8", []byte(res.IPv6.IP), clientIP, path, rawQuery)

	default:
		var lines []string
		if res.IPv4 != nil && res.IPv4.IP != "" {
			lines = append(lines, "ipv4: "+res.IPv4.IP)
		}
		if res.IPv6 != nil && res.IPv6.IP != "" {
			lines = append(lines, "ipv6: "+res.IPv6.IP)
		}
		if len(lines) == 0 {
			h.writeResponse(conn, method, 503, "Service Unavailable", "text/plain; charset=utf-8", []byte("no ip address available"), clientIP, path, rawQuery)
			return
		}
		h.writeResponse(conn, method, 200, "OK", "text/plain; charset=utf-8", []byte(strings.Join(lines, "\n")), clientIP, path, rawQuery)
	}
}

func (h *ServerHandler) writeError(conn net.Conn, method, format string, status int, reason, msg, clientIP, path, rawQuery string) {
	if format == "json" {
		var buf bytes.Buffer
		buf.WriteString(`{"error":`)
		writeJSONString(&buf, msg)
		buf.WriteByte('}')
		h.writeResponse(conn, method, status, reason, "application/json; charset=utf-8", buf.Bytes(), clientIP, path, rawQuery)
		return
	}
	h.writeResponse(conn, method, status, reason, "text/plain; charset=utf-8", []byte(msg), clientIP, path, rawQuery)
}

func (h *ServerHandler) writeResponse(conn net.Conn, method string, status int, reason, contentType string, body []byte, clientIP, path, rawQuery string) {
	var hdr bytes.Buffer
	hdr.Grow(160 + len(body))
	hdr.WriteString("HTTP/1.1 ")
	hdr.WriteString(strconv.Itoa(status))
	hdr.WriteByte(' ')
	hdr.WriteString(reason)
	hdr.WriteString("\r\nContent-Type: ")
	hdr.WriteString(contentType)
	hdr.WriteString("\r\nCache-Control: no-store\r\nContent-Length: ")
	hdr.WriteString(strconv.Itoa(len(body)))
	hdr.WriteString("\r\nConnection: close\r\n\r\n")
	if method != "HEAD" {
		hdr.Write(body)
	}
	_, _ = conn.Write(hdr.Bytes())
	h.logLine(strconv.Itoa(status) + " remote=" + clientIP + " method=" + method + " path=" + path + " query=" + redactQuery(rawQuery))
}

func (h *ServerHandler) logDrop(reason, remote, method, path, rawQuery string) {
	h.logLine("444 drop (" + reason + ") remote=" + remote + " method=" + method + " path=" + path + " query=" + redactQuery(rawQuery))
}

func (h *ServerHandler) logLine(msg string) {
	if h.logOut == nil {
		return
	}
	line := "[ip-api] " + h.now().UTC().Format(time.RFC3339) + " " + msg + "\n"
	h.logMu.Lock()
	_, _ = io.WriteString(h.logOut, line)
	h.logMu.Unlock()
}

func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, _, hasEq := strings.Cut(p, "=")
		if k == "token" && hasEq {
			parts[i] = "token=***"
		}
	}
	return strings.Join(parts, "&")
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

// --- Zero-reflection JSON encoder ---

func marshalOverviewJSON(ov OverviewResponse) []byte {
	var b bytes.Buffer
	b.Grow(512)
	b.WriteByte('{')
	first := true

	addComma := func() {
		if !first {
			b.WriteByte(',')
		}
		first = false
	}

	if ov.IPv4 != nil {
		addComma()
		b.WriteString(`"ipv4":`)
		writeIPResultJSON(&b, ov.IPv4)
	}
	if ov.IPv6 != nil {
		addComma()
		b.WriteString(`"ipv6":`)
		writeIPResultJSON(&b, ov.IPv6)
	}
	if len(ov.Interfaces) > 0 {
		addComma()
		b.WriteString(`"interfaces":[`)
		for i, iface := range ov.Interfaces {
			if i > 0 {
				b.WriteByte(',')
			}
			writeInterfaceInfoJSON(&b, iface)
		}
		b.WriteByte(']')
	}
	if ov.ClientIP != "" {
		addComma()
		b.WriteString(`"client_ip":`)
		writeJSONString(&b, ov.ClientIP)
	}
	if ov.Hostname != "" {
		addComma()
		b.WriteString(`"hostname":`)
		writeJSONString(&b, ov.Hostname)
	}
	addComma()
	b.WriteString(`"timestamp":`)
	writeJSONString(&b, ov.Timestamp)

	b.WriteByte('}')
	return b.Bytes()
}

func writeIPResultJSON(b *bytes.Buffer, r *IPResult) {
	b.WriteByte('{')
	first := true
	writeStr := func(k, v string) {
		if v == "" {
			return
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":`)
		writeJSONString(b, v)
	}
	writeStr("ip", r.IP)
	writeStr("source", r.Source)
	writeStr("iface", r.Iface)
	writeStr("probe", r.Probe)
	if r.Cached {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(`"cached":true`)
	}
	writeStr("error", r.Error)
	b.WriteByte('}')
}

func writeInterfaceInfoJSON(b *bytes.Buffer, info InterfaceInfo) {
	b.WriteString(`{"name":`)
	writeJSONString(b, info.Name)
	b.WriteString(`,"up":`)
	if info.Up {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	if info.MAC != "" {
		b.WriteString(`,"mac":`)
		writeJSONString(b, info.MAC)
	}
	if len(info.IPv4) > 0 {
		b.WriteString(`,"ipv4":`)
		writeJSONStringSlice(b, info.IPv4)
	}
	if len(info.IPv6) > 0 {
		b.WriteString(`,"ipv6":`)
		writeJSONStringSlice(b, info.IPv6)
	}
	b.WriteByte('}')
}

func writeJSONStringSlice(b *bytes.Buffer, items []string) {
	b.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(b, s)
	}
	b.WriteByte(']')
}

func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0x0f])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}
