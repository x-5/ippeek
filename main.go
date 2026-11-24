package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "[ippeek] ", log.LstdFlags)

	cfg, err := LoadConfig(os.Args[1:], os.Stderr)
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	prober := NewProber(cfg.V4Probes, cfg.V6Probes, cfg.ProbeTimeout, cfg.CacheTTL)
	resolver := NewResolver(OSInterfaceProvider{}, prober)
	handler := NewServerHandler(cfg.Token, resolver, cfg.TrustProxy, logger)

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler, // Mounted directly (no ServeMux) so all invalid paths drop with 444.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (cache_ttl=%s probe_timeout=%s v4_probes=%d v6_probes=%d)",
			cfg.Listen, cfg.CacheTTL, cfg.ProbeTimeout, len(cfg.V4Probes), len(cfg.V6Probes))
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server error: %v", err)
		}
	case sig := <-sigCh:
		logger.Printf("received signal %s, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("shutdown error: %v", err)
		}
		logger.Printf("stopped cleanly")
	}
}
