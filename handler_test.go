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
	"testing"
	"time"
)

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
	Timestamp  string          `json:"timestamp"`
}

func startTestTCPServer(t *testing.T, prober ExternalProber, ifaces []NetInterface) (string, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	resolver := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)
	handler := NewServerHandler("super-secret", resolver, false, &logBuf)
	handler.now = func() time.Time {
		return time.Date(2026, 11, 22, 17, 0, 0, 0, time.UTC)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler.HandleConn(ctx, conn)
		}
	}()

	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	return ln.Addr().String(), &logBuf
}

func TestHandlerDrop444OnNonConformingRequests(t *testing.T) {
	addr, logBuf := startTestTCPServer(t, &stubProber{}, nil)

	rawRequests := []struct {
		name string
		raw  string
	}{
		{"garbage non-http", "NOT EVEN HTTP\r\n\r\n"},
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
	addr, logBuf := startTestTCPServer(t, prober, ifaces)
	baseURL := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

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

	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "240e:3b1:1234::1" {
		t.Fatalf("v=6 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	resp, err = client.Get(baseURL + "/ip?token=super-secret")
	if err != nil {
		t.Fatalf("GET overview JSON failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("overview JSON status=%d body=%q", resp.StatusCode, string(body))
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
	if ov.ClientIP == "" || ov.Timestamp != "2026-11-22T17:00:00Z" {
		t.Fatalf("unexpected metadata: client_ip=%q timestamp=%q", ov.ClientIP, ov.Timestamp)
	}

	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=all&format=text")
	if err != nil {
		t.Fatalf("GET v=all text failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	wantDualText := "ipv4: 1.2.3.4\nipv6: 240e:3b1:1234::1"
	if resp.StatusCode != 200 || string(body) != wantDualText {
		t.Fatalf("dual text unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=4&iface=eth0&source=local")
	if err != nil {
		t.Fatalf("GET local eth0 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "192.168.1.10" {
		t.Fatalf("local eth0 unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	resp, err = client.Get(baseURL + "/ip?token=super-secret&v=4&iface=missing0")
	if err != nil {
		t.Fatalf("GET missing iface failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for missing iface, got %d", resp.StatusCode)
	}

	resp, err = client.Head(baseURL + "/ip?token=super-secret&v=4")
	if err != nil {
		t.Fatalf("HEAD v=4 failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) != 0 {
		t.Fatalf("HEAD unexpected: status=%d body=%q", resp.StatusCode, string(body))
	}

	if strings.Contains(logBuf.String(), "super-secret") {
		t.Fatalf("token leaked in logs:\n%s", logBuf.String())
	}
}

func TestHandlerUnavailableIPStatusCodes(t *testing.T) {
	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
		v6Err: errors.New("ipv6 unreachable"),
	}
	addr, _ := startTestTCPServer(t, prober, nil)
	baseURL := "http://" + addr
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(baseURL + "/ip?token=super-secret&v=6")
	if err != nil {
		t.Fatalf("GET v=6 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503 for unavailable v6 text, got %d", resp.StatusCode)
	}

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
