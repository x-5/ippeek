//go:build tiny

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func (p *Prober) probeAll(ctx context.Context, family IPFamily, probes []string, ifaceName string, localIP net.IP) (ProbeResult, error) {
	ctrl, err := makeDialerControl(ifaceName, localIP != nil)
	if err != nil {
		return ProbeResult{}, err
	}

	dialer := &net.Dialer{
		Timeout: p.timeout,
	}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	if ctrl != nil {
		dialer.Control = ctrl
	}

	var lastErr error
	for _, probeURL := range probes {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		ipStr, err := probeHTTPTiny(ctx, dialer, family, probeURL, p.timeout)
		if err == nil {
			return ProbeResult{
				IP:     ipStr,
				Probe:  probeURL,
				Cached: false,
			}, nil
		}
		wrapped := &netWrapError{
			msg: probeURL + ": " + err.Error(),
			err: err,
		}
		if errors.Is(err, ErrNoRoutableAddress) {
			return ProbeResult{}, wrapped
		}
		lastErr = wrapped
	}

	if lastErr == nil {
		lastErr = errors.New("all " + family.String() + " probes failed")
	}
	return ProbeResult{}, lastErr
}

func parseHTTPURL(raw string) (hostHeader, dialAddr, reqPath string, err error) {
	if strings.HasPrefix(raw, "https://") {
		return "", "", "", errors.New("https probes not supported in tiny build")
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

func probeHTTPTiny(ctx context.Context, dialer *net.Dialer, family IPFamily, rawURL string, timeout time.Duration) (string, error) {
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
	req.WriteString("\r\nUser-Agent: ippeek/1.0\r\nAccept: text/plain\r\nConnection: close\r\n\r\n")

	if _, err := io.WriteString(conn, req.String()); err != nil {
		return "", err
	}

	br := bufio.NewReaderSize(conn, 1024)
	statusLine, err := readProbeHeaderLine(br, 512)
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
	var contentLength int64 = -1
	headersDone := false
	for i := 0; i < 64; i++ {
		line, err := readProbeHeaderLine(br, 1024)
		if err != nil {
			return "", err
		}
		if line == "" {
			headersDone = true
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
		case "content-length":
			if cl, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil && cl >= 0 {
				contentLength = cl
			}
		}
	}
	if !headersDone {
		return "", errors.New("too many response headers")
	}

	if statusCode >= 300 && statusCode < 400 {
		return "", errors.New("redirects are disabled (HTTP " + strconv.Itoa(statusCode) + ")")
	}
	if statusCode != 200 {
		return "", errors.New("unexpected HTTP status " + strconv.Itoa(statusCode))
	}

	var rawBody []byte
	switch {
	case chunked:
		rawBody, err = readChunkedLimited(br, 128)
	case contentLength == 0:
		rawBody = nil
	case contentLength > 0 && contentLength <= 128:
		rawBody = make([]byte, contentLength)
		_, err = io.ReadFull(br, rawBody)
	default:
		rawBody, err = io.ReadAll(io.LimitReader(br, 128))
	}
	if err != nil {
		return "", err
	}

	return parseProbeIP(rawBody, family)
}

func readProbeHeaderLine(br *bufio.Reader, maxLen int) (string, error) {
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
		sizeLine, err := readProbeHeaderLine(br, 64)
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
		if _, err := readProbeHeaderLine(br, 16); err != nil {
			return nil, err
		}
	}
	return out, nil
}
