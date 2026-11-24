package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

func TestLoadConfig(t *testing.T) {
	t.Setenv("IP_API_TOKEN", "")
	var stderr bytes.Buffer

	// Missing token must fail.
	if _, err := LoadConfig([]string{}, &stderr); err == nil {
		t.Fatal("expected error when token is missing")
	}

	// Env var sets token and defaults.
	t.Setenv("IP_API_TOKEN", "env-secret")
	t.Setenv("IP_API_LISTEN", ":9090")
	cfg, err := LoadConfig([]string{}, &stderr)
	if err != nil {
		t.Fatalf("LoadConfig with env failed: %v", err)
	}
	if cfg.Token != "env-secret" || cfg.Listen != ":9090" {
		t.Fatalf("unexpected env config: %+v", cfg)
	}

	// CLI flag overrides env var.
	cfg, err = LoadConfig([]string{"-token", "cli-secret", "-listen", "127.0.0.1:7070", "-cache-ttl", "15s"}, &stderr)
	if err != nil {
		t.Fatalf("LoadConfig with flags failed: %v", err)
	}
	if cfg.Token != "cli-secret" || cfg.Listen != "127.0.0.1:7070" || cfg.CacheTTL != 15*time.Second {
		t.Fatalf("unexpected CLI config: %+v", cfg)
	}
}
