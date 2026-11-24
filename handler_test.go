package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, prober ExternalProber, ifaces []NetInterface) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)
	resolver := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)
	handler := NewServerHandler("super-secret", resolver, false, logger)
	handler.now = func() time.Time {
		return time.Date(2026, 11, 22, 17, 0, 0, 0, time.UTC)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, &logBuf
}

func TestHandlerDrop444OnNonConformingRequests(t *testing.T) {
	srv, logBuf := newTestServer(t, &stubProber{}, nil)
	addr := srv.Listener.Addr().String()

	rawRequests := []struct {
		name string
		raw  string
	}{
		{"root path", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"trailing slash", "GET /ip/ HTTP/1.1\r\nHost: localhost\r\n\r\n"},
		{"scanner path", "GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n"},
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
	srv, logBuf := newTestServer(t, prober, ifaces)
	client := srv.Client()

	// 1. Plain text IPv4 (default text for v=4)
	resp, err := client.Get(srv.URL + "/ip?token=super-secret&v=4")
	if err != nil {
		t.Fatalf("GET v=4 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "1.2.3.4" {
		t.Fatalf("v=4 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control=no-store, got %q", got)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("expected text/plain, got %q", resp.Header.Get("Content-Type"))
	}

	// 2. Plain text IPv6 (direct NIC public IPv6)
	resp, err = client.Get(srv.URL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "240e:3b1:1234::1" {
		t.Fatalf("v=6 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 3. Default overview JSON (v=all, format=json)
	resp, err = client.Get(srv.URL + "/ip?token=super-secret")
	if err != nil {
		t.Fatalf("GET overview JSON failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview JSON status=%d body=%q", resp.StatusCode, string(body))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json, got %q", resp.Header.Get("Content-Type"))
	}
	var ov OverviewResponse
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("unmarshal overview JSON failed: %v", err)
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
	if ov.ClientIP == "" || ov.Timestamp != "2026-11-22T17:00:00Z" {
		t.Fatalf("unexpected metadata: client_ip=%q timestamp=%q", ov.ClientIP, ov.Timestamp)
	}

	// 4. Dual-stack plain text (v=all&format=text)
	resp, err = client.Get(srv.URL + "/ip?token=super-secret&v=all&format=text")
	if err != nil {
		t.Fatalf("GET v=all text failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	wantDualText := "ipv4: 1.2.3.4\nipv6: 240e:3b1:1234::1"
	if resp.StatusCode != http.StatusOK || string(body) != wantDualText {
		t.Fatalf("dual text unexpected: status=%d body=%q want=%q", resp.StatusCode, string(body), wantDualText)
	}

	// 5. Local NIC IP via iface + source=local
	resp, err = client.Get(srv.URL + "/ip?token=super-secret&v=4&iface=eth0&source=local")
	if err != nil {
		t.Fatalf("GET local eth0 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "192.168.1.10" {
		t.Fatalf("local eth0 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 6. Nonexistent interface returns 404
	resp, err = client.Get(srv.URL + "/ip?token=super-secret&v=4&iface=missing0")
	if err != nil {
		t.Fatalf("GET missing iface failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for missing iface, got %d", resp.StatusCode)
	}

	// 7. HEAD request returns 200 with empty body
	resp, err = client.Head(srv.URL + "/ip?token=super-secret&v=4")
	if err != nil {
		t.Fatalf("HEAD v=4 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(body) != 0 {
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
	srv, _ := newTestServer(t, prober, nil)
	client := srv.Client()

	// Text mode for missing IPv6 returns 503.
	resp, err := client.Get(srv.URL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for unavailable v6 text, got %d", resp.StatusCode)
	}

	// JSON mode still returns 200 with ipv6.error populated alongside valid ipv4.
	resp, err = client.Get(srv.URL + "/ip?token=super-secret")
	if err != nil {
		t.Fatalf("GET overview failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for partial JSON overview, got %d", resp.StatusCode)
	}
	var ov OverviewResponse
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
