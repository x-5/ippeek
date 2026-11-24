package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestProberFallbackAndValidation(t *testing.T) {
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer srvErr.Close()

	srvHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>captive portal</body></html>"))
	}))
	defer srvHTML.Close()

	srvWrongFamily := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("240e:3b1::1\n"))
	}))
	defer srvWrongFamily.Close()

	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("  1.2.3.4 \n"))
	}))
	defer srvGood.Close()

	prober := NewProber(
		[]string{srvErr.URL, srvHTML.URL, srvWrongFamily.URL, srvGood.URL},
		nil,
		2*time.Second,
		30*time.Second,
	)

	res, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if res.IP != "1.2.3.4" || res.Probe != srvGood.URL || res.Cached {
		t.Fatalf("unexpected ProbeResult: %+v", res)
	}
}

func TestProberChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("8.8."))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("8.8\n"))
	}))
	defer srv.Close()

	prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 30*time.Second)
	res, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil {
		t.Fatalf("Probe chunked failed: %v", err)
	}
	if res.IP != "8.8.8.8" {
		t.Fatalf("expected 8.8.8.8, got %+v", res)
	}
}

func TestProberRejectsRedirectsAndFallsBack(t *testing.T) {
	var targetHits atomic.Int32
	srvTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("10.0.0.1\n"))
	}))
	defer srvTarget.Close()

	srv302 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvTarget.URL, http.StatusFound)
	}))
	defer srv302.Close()

	srv301 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvTarget.URL, http.StatusMovedPermanently)
	}))
	defer srv301.Close()

	srvFallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("9.8.7.6\n"))
	}))
	defer srvFallback.Close()

	// 302/301 redirects must be rejected without touching the redirect target and fall back to next probe.
	prober := NewProber([]string{srv302.URL, srv301.URL, srvFallback.URL}, nil, 2*time.Second, 0)
	res, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil {
		t.Fatalf("expected fallback probe to succeed, got %v", err)
	}
	if res.IP != "9.8.7.6" || res.Probe != srvFallback.URL {
		t.Fatalf("unexpected result: %+v", res)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("expected redirect target to receive 0 requests, got %d", got)
	}

	// Single 302 probe must fail with a redirect error.
	onlyRedirect := NewProber([]string{srv302.URL}, nil, 2*time.Second, 0)
	_, err = onlyRedirect.Probe(context.Background(), FamilyV4, "", nil, false)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect error, got %v", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("expected redirect target to still have 0 requests, got %d", got)
	}
}

func TestProberKeepAliveContentLength(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	release := make(chan struct{})
	defer close(release)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		// Respond with Content-Length and Connection: keep-alive, then intentionally delay closing.
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: keep-alive\r\n\r\n1.2.3.4\n")

		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
	}()

	probeURL := "http://" + ln.Addr().String() + "/"
	prober := NewProber([]string{probeURL}, nil, 1*time.Second, 0)

	start := time.Now()
	res, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("keep-alive Content-Length probe failed after %v: %v", elapsed, err)
	}
	if res.IP != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %+v", res)
	}
	if elapsed >= 400*time.Millisecond {
		t.Fatalf("expected immediate return via Content-Length, took %v", elapsed)
	}
}

func TestProberStrictIfaceBinding(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("1.2.3.4"))
	}))
	defer srv.Close()

	// Case 1: explicit iface + nil localIP + EPERM on SO_BINDTODEVICE must fail with ErrNoRoutableAddress
	// and never fall back to the default route.
	t.Run("no_local_ip_eperm_rejects", func(t *testing.T) {
		hits.Store(0)
		origHook := bindToDeviceHook
		bindToDeviceHook = func(fd int, ifaceName string) error {
			return syscall.EPERM
		}
		defer func() { bindToDeviceHook = origHook }()

		prober := NewProber([]string{srv.URL, srv.URL}, nil, 2*time.Second, 0)
		_, err := prober.Probe(context.Background(), FamilyV4, "eth99", nil, false)
		if !errors.Is(err, ErrNoRoutableAddress) {
			t.Fatalf("expected ErrNoRoutableAddress, got %v", err)
		}
		if got := hits.Load(); got != 0 {
			t.Fatalf("expected 0 upstream hits when binding fails, got %d", got)
		}
	})

	// Case 2: explicit iface + nil localIP + EACCES on SO_BINDTODEVICE must also reject.
	t.Run("no_local_ip_eacces_rejects", func(t *testing.T) {
		hits.Store(0)
		origHook := bindToDeviceHook
		bindToDeviceHook = func(fd int, ifaceName string) error {
			return syscall.EACCES
		}
		defer func() { bindToDeviceHook = origHook }()

		prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 0)
		_, err := prober.Probe(context.Background(), FamilyV4, "eth99", nil, false)
		if !errors.Is(err, ErrNoRoutableAddress) {
			t.Fatalf("expected ErrNoRoutableAddress, got %v", err)
		}
		if got := hits.Load(); got != 0 {
			t.Fatalf("expected 0 upstream hits when binding fails, got %d", got)
		}
	})

	// Case 3: explicit iface + valid localIP + EPERM on SO_BINDTODEVICE falls back to LocalAddr and succeeds.
	t.Run("with_local_ip_eperm_uses_local_addr", func(t *testing.T) {
		hits.Store(0)
		origHook := bindToDeviceHook
		bindToDeviceHook = func(fd int, ifaceName string) error {
			return syscall.EPERM
		}
		defer func() { bindToDeviceHook = origHook }()

		prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 0)
		res, err := prober.Probe(context.Background(), FamilyV4, "lo", net.ParseIP("127.0.0.1"), false)
		if err != nil {
			t.Fatalf("expected LocalAddr fallback to succeed, got %v", err)
		}
		if res.IP != "1.2.3.4" || hits.Load() != 1 {
			t.Fatalf("unexpected result=%+v hits=%d", res, hits.Load())
		}
	})
}

func TestProberCacheTTLAndRefresh(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			_, _ = w.Write([]byte("1.2.3.4"))
			return
		}
		_, _ = w.Write([]byte("5.6.7.8"))
	}))
	defer srv.Close()

	curTime := time.Date(2026, 11, 22, 17, 0, 0, 0, time.UTC)
	prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 60*time.Second)
	prober.now = func() time.Time { return curTime }

	// First call populates cache.
	r1, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil || r1.IP != "1.2.3.4" || r1.Cached {
		t.Fatalf("first probe unexpected: res=%+v err=%v", r1, err)
	}

	// Second call hits cache without calling server.
	r2, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil || r2.IP != "1.2.3.4" || !r2.Cached {
		t.Fatalf("cached probe unexpected: res=%+v err=%v", r2, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 hit after cache hit, got %d", hits.Load())
	}

	// Forced refresh bypasses cache and updates it.
	r3, err := prober.Probe(context.Background(), FamilyV4, "", nil, true)
	if err != nil || r3.IP != "5.6.7.8" || r3.Cached {
		t.Fatalf("refresh probe unexpected: res=%+v err=%v", r3, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 hits after refresh, got %d", hits.Load())
	}

	// Advancing clock past TTL expires cache.
	curTime = curTime.Add(61 * time.Second)
	r4, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
	if err != nil || r4.IP != "5.6.7.8" || r4.Cached {
		t.Fatalf("post-expiry probe unexpected: res=%+v err=%v", r4, err)
	}
	if hits.Load() != 3 {
		t.Fatalf("expected 3 hits after TTL expiry, got %d", hits.Load())
	}
}

func TestProberInflightCoalescing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(60 * time.Millisecond)
		_, _ = w.Write([]byte("9.9.9.9"))
	}))
	defer srv.Close()

	prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 30*time.Second)

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			res, err := prober.Probe(context.Background(), FamilyV4, "", nil, false)
			if err != nil {
				errs <- err
				return
			}
			if res.IP != "9.9.9.9" {
				errs <- context.DeadlineExceeded
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent probe failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected concurrent probes to coalesce into 1 upstream request, got %d", got)
	}
}
