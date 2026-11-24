package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type jsonIPResult struct {
	IP     string `json:"ip"`
	Source string `json:"source"`
	Iface  string `json:"iface"`
	Probe  string `json:"probe"`
	Cached bool   `json:"cached"`
	Error  string `json:"error"`
}

type jsonIfaceInfo struct {
	Name string   `json:"name"`
	Up   bool     `json:"up"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type jsonOverview struct {
	IPv4       *jsonIPResult   `json:"ipv4"`
	IPv6       *jsonIPResult   `json:"ipv6"`
	Interfaces []jsonIfaceInfo `json:"interfaces"`
	ClientIP   string          `json:"client_ip"`
	Hostname   string          `json:"hostname"`
	Version    string          `json:"version"`
	Timestamp  string          `json:"timestamp"`
}

func startTestServer(t *testing.T, tokens []string, prober ExternalProber, ifaces []NetInterface, trustProxy, quietDrops bool, customize func(*ServerHandler)) (string, *lockedBuffer, *ServerHandler) {
	t.Helper()
	logBuf := &lockedBuffer{}
	resolver := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)
	handler := NewServerHandler(tokens, resolver, trustProxy, quietDrops, logBuf)
	handler.now = func() time.Time {
		return time.Date(2026, 11, 22, 17, 0, 0, 0, time.UTC)
	}
	if customize != nil {
		customize(handler)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handler.serve(ctx, ln)
	}()

	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), logBuf, handler
}

func TestHandlerDrop444OnNonConformingRequests(t *testing.T) {
	addr, logBuf, _ := startTestServer(t, []string{"super-secret"}, &stubProber{}, nil, false, false, nil)

	rawRequests := []struct {
		name string
		raw  string
	}{
		{"root path", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"trailing slash", "GET /ip/ HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"scanner path", "GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"encoded path", "GET /%69%70?token=super-secret HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"wrong method POST", "POST /ip?token=super-secret HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"},
		{"missing token", "GET /ip HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"empty token", "GET /ip?token= HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"wrong token", "GET /ip?token=wrong-token&v=4 HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"invalid v", "GET /ip?token=super-secret&v=9 HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"invalid format", "GET /ip?token=super-secret&format=xml HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"invalid source", "GET /ip?token=super-secret&source=dns HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"invalid refresh", "GET /ip?token=super-secret&refresh=yes HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"unknown query key", "GET /ip?token=super-secret&foo=bar HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"duplicate query key", "GET /ip?token=super-secret&v=4&v=6 HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"malformed query", "GET /ip?token=super-secret&bad=%ZZ HTTP/1.1\r\nHost: localhost\r\n\r\n"},
	}

	for _, tc := range rawRequests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

			if _, err := conn.Write([]byte(tc.raw)); err != nil {
				t.Fatalf("write failed: %v", err)
			}

			data, err := io.ReadAll(conn)
			if len(data) != 0 {
				t.Fatalf("expected 0 response bytes (444 drop), got %d bytes: %q (err=%v)", len(data), string(data), err)
			}
		})
	}

	logs := logBuf.String()
	if strings.Contains(logs, "super-secret") || strings.Contains(logs, "wrong-token") {
		t.Fatalf("expected tokens to be redacted from logs, got:\n%s", logs)
	}
	if !strings.Contains(logs, "token=***") {
		t.Fatalf("expected redacted token marker in logs, got:\n%s", logs)
	}
}

func TestTokenRedactionAndLogInjection(t *testing.T) {
	// Unit-level checks on redactQuery and sanitizeLogField.
	redactCases := []struct {
		in   string
		want string
	}{
		{"token=SECRET&v=4", "token=***&v=4"},
		{"%74oken=SECRET&v=4", "token=***&v=4"},
		{"%74%6f%6b%65%6e=SECRET", "token=***"},
		{"v=4;token=SECRET", "v=4;token=***"},
		{"v=4;%74oken=SECRET&bad=%ZZ", "v=4;token=***&bad=%ZZ"},
		{"Token=SECRET&v=4", "token=***&v=4"},
	}
	for _, tc := range redactCases {
		if got := redactQuery(tc.in); got != tc.want {
			t.Errorf("redactQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	sanitized := sanitizeLogField("GET\r\n[ippeek] 200\x1b[31m\x7f")
	if strings.ContainsAny(sanitized, "\r\n\x1b\x7f") {
		t.Fatalf("sanitizeLogField left control chars: %q", sanitized)
	}

	// End-to-end checks over real server (std and tiny).
	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
	}
	addr, logBuf, _ := startTestServer(t, []string{"top-secret-999"}, prober, nil, false, false, nil)

	// 1. Percent-encoded %74oken=top-secret-999 must authenticate and redact token in logs.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/ip?%74oken=top-secret-999&v=4")
	if err != nil {
		t.Fatalf("GET %%74oken failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "1.2.3.4" {
		t.Fatalf("%%74oken unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 2. Malformed header & too many headers with token in query must NEVER leak token.
	tooManyHdrs := "GET /ip?token=top-secret-999 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" +
		strings.Repeat("X-Pad: 1\r\n", 70) + "\r\n"
	badHeaderReqs := []string{
		"GET /ip?token=top-secret-999 HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n",
		"GET /ip?%74oken=top-secret-999 HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n",
		tooManyHdrs,
		"GET /ip?token=top-secret-999&bad=%ZZ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	}
	for _, raw := range badHeaderReqs {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte(raw))
		data, _ := io.ReadAll(conn)
		_ = conn.Close()
		if serverEdition == "tiny" && len(data) != 0 {
			t.Fatalf("tiny server must drop malformed/excess headers with 0 bytes, got %q", string(data))
		}
	}

	// 3. Log injection via %0a / %0d in path must NOT inject a new log line.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("GET /bad%0d%0a[ippeek]%20200%20FORGED_LINE?token=top-secret-999 HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	data, _ := io.ReadAll(conn)
	_ = conn.Close()
	if len(data) != 0 {
		t.Fatalf("expected 444 drop on log-injection path, got %q", string(data))
	}

	// Give server a tiny moment to flush final log write.
	time.Sleep(20 * time.Millisecond)

	logs := logBuf.String()
	if strings.Contains(logs, "top-secret-999") {
		t.Fatalf("token leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, "token=***") {
		t.Fatalf("expected token=*** in logs:\n%s", logs)
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if !strings.HasPrefix(line, "[ippeek] 2026-11-22T17:00:00Z ") {
			t.Fatalf("log injection detected (unexpected line prefix): %q\nfull logs:\n%s", line, logs)
		}
		for i := 0; i < len(line); i++ {
			if line[i] < 0x20 || line[i] == 0x7f {
				t.Fatalf("control character 0x%02x leaked into log line: %q", line[i], line)
			}
		}
	}
}

func TestHandlerValidRequestsTextAndJSON(t *testing.T) {
	ifaces := []NetInterface{
		{
			Name: "eth0",
			Up:   true,
			MAC:  "aa:bb:cc:dd:ee:ff",
			IPv4: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			IPv6: []netip.Addr{netip.MustParseAddr("240e:3b1:1234::1"), netip.MustParseAddr("fe80::1")},
		},
	}
	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
		v6Err: errors.New("no ipv6 probe"),
	}
	addr, logBuf, _ := startTestServer(t, []string{"super-secret"}, prober, ifaces, false, false, nil)
	baseURL := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Plain text IPv4 (default text for v=4)
	resp, err := client.Get(baseURL + "/ip?token=super-secret&v=4")
	if err != nil {
		t.Fatalf("GET v=4 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "1.2.3.4" {
		t.Fatalf("v=4 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control=no-store, got %q", got)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("expected text/plain, got %q", resp.Header.Get("Content-Type"))
	}

	// 2. Plain text IPv6 (direct NIC public IPv6)
	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "240e:3b1:1234::1" {
		t.Fatalf("v=6 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 3. Default overview JSON (v=all, format=json)
	resp, err = client.Get(baseURL + "/ip?token=super-secret")
	if err != nil {
		t.Fatalf("GET overview JSON failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("overview JSON status=%d body=%q", resp.StatusCode, string(body))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json, got %q", resp.Header.Get("Content-Type"))
	}
	var ov jsonOverview
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("unmarshal overview JSON failed: %v (raw=%s)", err, string(body))
	}
	if ov.IPv4 == nil || ov.IPv4.IP != "1.2.3.4" || ov.IPv4.Source != "external" {
		t.Fatalf("unexpected overview IPv4: %+v", ov.IPv4)
	}
	if ov.IPv6 == nil || ov.IPv6.IP != "240e:3b1:1234::1" || ov.IPv6.Source != "interface" {
		t.Fatalf("unexpected overview IPv6: %+v", ov.IPv6)
	}
	if len(ov.Interfaces) != 1 || ov.Interfaces[0].Name != "eth0" {
		t.Fatalf("unexpected overview interfaces: %+v", ov.Interfaces)
	}
	if ov.ClientIP == "" || ov.Timestamp != "2026-11-22T17:00:00Z" || ov.Version != version {
		t.Fatalf("unexpected metadata: client_ip=%q timestamp=%q version=%q", ov.ClientIP, ov.Timestamp, ov.Version)
	}

	// 4. Dual-stack plain text (v=all&format=text)
	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=all&format=text")
	if err != nil {
		t.Fatalf("GET v=all text failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	wantDualText := "ipv4: 1.2.3.4\nipv6: 240e:3b1:1234::1"
	if resp.StatusCode != 200 || string(body) != wantDualText {
		t.Fatalf("dual text unexpected: status=%d body=%q want=%q", resp.StatusCode, string(body), wantDualText)
	}

	// 5. Local NIC IP via iface + source=local
	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=4&iface=eth0&source=local")
	if err != nil {
		t.Fatalf("GET local eth0 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "192.168.1.10" {
		t.Fatalf("local eth0 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 6. Nonexistent interface returns 404
	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=4&iface=missing0")
	if err != nil {
		t.Fatalf("GET missing iface failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for missing iface, got %d", resp.StatusCode)
	}

	// 7. HEAD request returns 200 with empty body
	resp, err = client.Head(baseURL + "/ip?token=super-secret&v=4")
	if err != nil {
		t.Fatalf("HEAD v=4 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) != 0 {
		t.Fatalf("HEAD unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// Verify token never leaked in access logs
	if strings.Contains(logBuf.String(), "super-secret") {
		t.Fatalf("token leaked in logs:\n%s", logBuf.String())
	}
}

func TestHandlerUnavailableIPStatusCodes(t *testing.T) {
	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
		v6Err: errors.New("ipv6 unreachable"),
	}
	addr, _, _ := startTestServer(t, []string{"super-secret"}, prober, nil, false, false, nil)
	baseURL := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

	// Text mode for missing IPv6 returns 503.
	resp, err := client.Get(baseURL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503 for unavailable v6 text, got %d", resp.StatusCode)
	}

	// JSON mode still returns 200 with ipv6.error populated alongside valid ipv4.
	resp, err = client.Get(baseURL + "/ip?token=super-secret")
	if err != nil {
		t.Fatalf("GET overview failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for partial JSON overview, got %d", resp.StatusCode)
	}
	var ov jsonOverview
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if ov.IPv4 == nil || ov.IPv4.IP != "1.2.3.4" {
		t.Fatalf("expected valid IPv4 in partial overview: %+v", ov.IPv4)
	}
	if ov.IPv6 == nil || ov.IPv6.Error == "" {
		t.Fatalf("expected ipv6 error in partial overview: %+v", ov.IPv6)
	}
}
