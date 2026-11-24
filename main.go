package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const maxConcurrentConns = 128

func main() {
	cfg, err := LoadConfig(os.Args[1:])
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "[ippeek] config error: "+err.Error()+"\n")
		os.Exit(1)
	}

	prober := NewProber(cfg.V4Probes, cfg.V6Probes, cfg.ProbeTimeout, cfg.CacheTTL)
	resolver := NewResolver(OSInterfaceProvider{}, prober)
	handler := NewServerHandler(cfg.Token, resolver, cfg.TrustProxy, os.Stdout)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "[ippeek] listen error: "+err.Error()+"\n")
		os.Exit(1)
	}

	_, _ = io.WriteString(os.Stdout,
		"[ippeek] listening on "+ln.Addr().String()+
			" (go-tiny cache_ttl="+cfg.CacheTTL.String()+
			" probe_timeout="+cfg.ProbeTimeout.String()+
			" v4_probes="+strconv.Itoa(len(cfg.V4Probes))+
			" v6_probes="+strconv.Itoa(len(cfg.V6Probes))+")\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentConns)

	go func() {
		sig := <-sigCh
		_, _ = io.WriteString(os.Stdout, "[ippeek] received signal "+sig.String()+", shutting down...\n")
		cancel()
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
				handler.HandleConn(ctx, c)
			}(conn)
		default:
			// Drop excess connections immediately under load.
			_ = conn.Close()
		}
	}

	wg.Wait()
	_, _ = io.WriteString(os.Stdout, "[ippeek] stopped cleanly\n")
}
