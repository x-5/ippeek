//go:build !tiny

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const serverEdition = "std"

// ServerHandler serves the single /ip endpoint via net/http and drops all non-conforming requests (Nginx 444 semantics).
type ServerHandler struct {
	handlerCore
}

// NewServerHandler constructs a ServerHandler.
func NewServerHandler(tokens []string, resolver *Resolver, trustProxy, quietDrops bool, logOut io.Writer) *ServerHandler {
	return &ServerHandler{
		handlerCore: newHandlerCore(tokens, resolver, trustProxy, quietDrops, logOut),
	}
}

// ServeHTTP validates every incoming request strictly and drops non-conforming connections with 0 bytes written.
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawPath != "" || r.URL.Path != "/ip" {
		h.drop(w, r, "invalid_path")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.drop(w, r, "invalid_method")
		return
	}
	if r.ContentLength > 0 || r.ContentLength == -1 ||
		len(r.TransferEncoding) > 0 ||
		len(r.Header.Values("Transfer-Encoding")) > 0 ||
		len(r.Header.Values("Content-Length")) > 1 {
		h.drop(w, r, "unexpected_body_header")
		return
	}

	q, ok := parseStrictQuery(r.URL.RawQuery)
	if !ok {
		h.drop(w, r, "invalid_query")
		return
	}

	if !h.matchToken(q["token"]) {
		h.drop(w, r, "unauthorized")
		return
	}

	opts, format, ok := parseValidParams(q)
	if !ok {
		h.drop(w, r, "invalid_param_value")
		return
	}

	reqCtx, cancel := context.WithTimeout(r.Context(), h.requestTimeout)
	defer cancel()

	res, err := h.resolver.Resolve(reqCtx, opts)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			h.writeError(w, r, format, http.StatusNotFound, err.Error())
			return
		}
		h.writeError(w, r, format, http.StatusInternalServerError, err.Error())
		return
	}

	clientIP := h.reqClientIP(r)
	if format == "json" {
		payload := OverviewResponse{
			Version:    version,
			IPv4:       res.IPv4,
			IPv6:       res.IPv6,
			Interfaces: res.Interfaces,
			ClientIP:   clientIP,
			Hostname:   h.hostname,
			Timestamp:  h.now().UTC().Format(time.RFC3339),
		}
		h.writeJSON(w, r, http.StatusOK, payload)
		return
	}

	status, _, body := formatTextResult(opts.Version, res)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.writeRawText(w, r, status, body)
}

func (h *ServerHandler) reqClientIP(r *http.Request) string {
	return extractClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustProxy)
}

func (h *ServerHandler) writeRawText(w http.ResponseWriter, r *http.Request, status int, body string) {
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	h.logAccess(status, h.reqClientIP(r), r.Method, r.URL.Path, r.URL.RawQuery)
}

func (h *ServerHandler) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		h.writeError(w, r, "text", http.StatusInternalServerError, "failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
	h.logAccess(status, h.reqClientIP(r), r.Method, r.URL.Path, r.URL.RawQuery)
}

func (h *ServerHandler) writeError(w http.ResponseWriter, r *http.Request, format string, status int, msg string) {
	if format == "json" {
		h.writeJSON(w, r, status, map[string]string{"error": msg})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.writeRawText(w, r, status, msg)
}

func (h *ServerHandler) drop(w http.ResponseWriter, r *http.Request, reason string) {
	h.logDrop(reason, h.reqClientIP(r), r.Method, r.URL.Path, r.URL.RawQuery)
	dropConn(w)
}

// dropConn terminates the underlying TCP connection without sending any HTTP response bytes (Nginx 444 semantics).
func dropConn(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	if conn, _, err := rc.Hijack(); err == nil {
		_ = conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

func (h *ServerHandler) serve(ctx context.Context, ln net.Listener) error {
	limitedLn := newLimitedListener(ln, h.maxConns, h.maxConnsPerIP, func(reason, ip string) {
		h.logDrop(reason, ip, "", "", "")
	})
	server := &http.Server{
		Handler:           h, // Mounted directly (no ServeMux) so all invalid paths drop with 444.
		ReadHeaderTimeout: h.readHeaderTimeout,
		ReadTimeout:       h.requestTimeout,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4096,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(limitedLn)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), h.shutdownTimeout)
		defer cancel()
		err := server.Shutdown(shutCtx)
		if err != nil {
			_ = server.Close()
		}
		<-errCh
		return err
	}
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
