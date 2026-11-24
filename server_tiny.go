//go:build tiny

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	serverEdition      = "tiny"
	maxReqHeadersBytes = 4096
	maxReqHeaderLines  = 64
	maxConcurrentConns = 128
)

// ServerHandler serves the single /ip endpoint over raw TCP connections
// and drops all non-conforming requests with 0 response bytes (Nginx 444 semantics).
type ServerHandler struct {
	handlerCore
}

// NewServerHandler constructs a ServerHandler.
func NewServerHandler(tokens []string, resolver *Resolver, trustProxy, quietDrops bool, logOut io.Writer) *ServerHandler {
	return &ServerHandler{
		handlerCore: newHandlerCore(tokens, resolver, trustProxy, quietDrops, logOut),
	}
}

// HandleConn processes a single TCP connection and closes it when done.
func (h *ServerHandler) HandleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(h.requestTimeout))

	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	remoteIP := peerIP(conn.RemoteAddr())

	br := bufio.NewReaderSize(io.LimitReader(conn, maxReqHeadersBytes), 1024)
	reqLine, err := readReqHeaderLine(br, 1024)
	if err != nil {
		h.logDrop("malformed_request", remoteIP, "", "", "")
		return
	}

	method, target, proto, ok := parseRequestLine(reqLine)
	if !ok {
		h.logDrop("malformed_request_line", remoteIP, "", "", "")
		return
	}
	_ = proto
	path, rawQuery, _ := strings.Cut(target, "?")

	var xff, xri string
	headersDone := false
	for i := 0; i < maxReqHeaderLines; i++ {
		line, err := readReqHeaderLine(br, 1024)
		if err != nil {
			h.logDrop("malformed_headers", remoteIP, method, path, rawQuery)
			return
		}
		if line == "" {
			headersDone = true
			break
		}
		k, v, hasColon := strings.Cut(line, ":")
		if !hasColon {
			h.logDrop("malformed_header_line", remoteIP, method, path, rawQuery)
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
		h.logDrop("too_many_headers", remoteIP, method, path, rawQuery)
		return
	}

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

	if !h.matchToken(q["token"]) {
		h.logDrop("unauthorized", clientIP, method, path, rawQuery)
		return
	}

	opts, format, ok := parseValidParams(q)
	if !ok {
		h.logDrop("invalid_param_value", clientIP, method, path, rawQuery)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.requestTimeout)
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
		body := marshalOverviewJSON(payload, version)
		h.writeResponse(conn, method, 200, "OK", "application/json; charset=utf-8", body, clientIP, path, rawQuery)
		return
	}

	status, reason, body := formatTextResult(opts.Version, res)
	h.writeResponse(conn, method, status, reason, "text/plain; charset=utf-8", []byte(body), clientIP, path, rawQuery)
}

func readReqHeaderLine(br *bufio.Reader, maxLen int) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLen {
		return "", errors.New("header line too long")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if strings.IndexByte(line, '\r') >= 0 {
		return "", errors.New("bare carriage return")
	}
	return line, nil
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
	h.logAccess(status, clientIP, method, path, rawQuery)
}

func (h *ServerHandler) serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentConns)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(c net.Conn) {
				defer func() {
					<-sem
					wg.Done()
				}()
				h.HandleConn(ctx, c)
			}(conn)
		default:
			_ = conn.Close()
		}
	}

	wg.Wait()
	return nil
}

func runServer(cfg Config, resolver *Resolver) error {
	handler := NewServerHandler(cfg.Tokens, resolver, cfg.TrustProxy, cfg.QuietDrops, os.Stdout)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	_, _ = io.WriteString(os.Stdout,
		"[ippeek] listening on "+ln.Addr().String()+
			" ("+serverEdition+
			" version="+version+
			" cache_ttl="+cfg.CacheTTL.String()+
			" probe_timeout="+cfg.ProbeTimeout.String()+
			" v4_probes="+strconv.Itoa(len(cfg.V4Probes))+
			" v6_probes="+strconv.Itoa(len(cfg.V6Probes))+")\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case sig := <-sigCh:
			_, _ = io.WriteString(os.Stdout, "[ippeek] received signal "+sig.String()+", shutting down...\n")
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := handler.serve(ctx, ln); err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, "[ippeek] stopped cleanly\n")
	return nil
}

// --- Zero-reflection JSON encoder ---

func marshalOverviewJSON(ov OverviewResponse, ver string) []byte {
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
	if ver != "" {
		addComma()
		b.WriteString(`"version":`)
		writeJSONString(&b, ver)
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
