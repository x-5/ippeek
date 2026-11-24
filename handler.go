package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

var allowedQueryKeys = map[string]struct{}{
	"token":   {},
	"v":       {},
	"format":  {},
	"iface":   {},
	"source":  {},
	"refresh": {},
}

// ServerHandler serves the single /ip endpoint and drops all non-conforming requests (Nginx 444 semantics).
type ServerHandler struct {
	token      []byte
	resolver   *Resolver
	trustProxy bool
	logger     *log.Logger
	hostname   string
	now        func() time.Time
}

// NewServerHandler constructs a ServerHandler.
func NewServerHandler(token string, resolver *Resolver, trustProxy bool, logger *log.Logger) *ServerHandler {
	hostname, _ := os.Hostname()
	return &ServerHandler{
		token:      []byte(token),
		resolver:   resolver,
		trustProxy: trustProxy,
		logger:     logger,
		hostname:   hostname,
		now:        time.Now,
	}
}

// ServeHTTP validates every incoming request strictly and drops non-conforming connections with 0 bytes written.
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ip" {
		h.drop(w, r, "invalid_path")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.drop(w, r, "invalid_method")
		return
	}

	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		h.drop(w, r, "malformed_query")
		return
	}

	for key, vals := range q {
		if _, ok := allowedQueryKeys[key]; !ok || len(vals) != 1 {
			h.drop(w, r, "invalid_query_key")
			return
		}
	}

	gotToken := q.Get("token")
	if len(gotToken) == 0 || subtle.ConstantTimeCompare([]byte(gotToken), h.token) != 1 {
		h.drop(w, r, "unauthorized")
		return
	}

	opts, format, ok := parseValidParams(q)
	if !ok {
		h.drop(w, r, "invalid_param_value")
		return
	}

	res, err := h.resolver.Resolve(r.Context(), opts)
	if err != nil {
		if errors.Is(err, ErrInterfaceNotFound) {
			h.writeError(w, r, format, http.StatusNotFound, err.Error())
			return
		}
		h.writeError(w, r, format, http.StatusInternalServerError, err.Error())
		return
	}

	if format == "json" {
		payload := OverviewResponse{
			IPv4:       res.IPv4,
			IPv6:       res.IPv6,
			Interfaces: res.Interfaces,
			ClientIP:   extractClientIP(r, h.trustProxy),
			Hostname:   h.hostname,
			Timestamp:  h.now().UTC().Format(time.RFC3339),
		}
		h.writeJSON(w, r, http.StatusOK, payload)
		return
	}

	h.writeTextResult(w, r, opts.Version, res)
}

func parseValidParams(q url.Values) (ResolveOptions, string, bool) {
	version := q.Get("v")
	switch version {
	case "", "all":
		version = "all"
	case "4", "6":
	default:
		return ResolveOptions{}, "", false
	}

	format := q.Get("format")
	switch format {
	case "":
		if version == "4" || version == "6" {
			format = "text"
		} else {
			format = "json"
		}
	case "text", "json":
	default:
		return ResolveOptions{}, "", false
	}

	var source SourceMode
	switch q.Get("source") {
	case "", "auto":
		source = SourceAuto
	case "local":
		source = SourceLocal
	case "external":
		source = SourceExternal
	default:
		return ResolveOptions{}, "", false
	}

	refresh := false
	switch q.Get("refresh") {
	case "", "0", "false":
		refresh = false
	case "1", "true":
		refresh = true
	default:
		return ResolveOptions{}, "", false
	}

	iface := q.Get("iface")
	if len(iface) > 64 || !isValidIfaceName(iface) {
		return ResolveOptions{}, "", false
	}

	return ResolveOptions{
		Version: version,
		Iface:   iface,
		Source:  source,
		Refresh: refresh,
	}, format, true
}

func isValidIfaceName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func (h *ServerHandler) writeTextResult(w http.ResponseWriter, r *http.Request, version string, res ResolveOutput) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	switch version {
	case "4":
		if res.IPv4 == nil || res.IPv4.IP == "" {
			msg := "no ipv4 address available"
			if res.IPv4 != nil && res.IPv4.Error != "" {
				msg = res.IPv4.Error
			}
			h.writeRawText(w, r, http.StatusServiceUnavailable, msg)
			return
		}
		h.writeRawText(w, r, http.StatusOK, res.IPv4.IP)

	case "6":
		if res.IPv6 == nil || res.IPv6.IP == "" {
			msg := "no ipv6 address available"
			if res.IPv6 != nil && res.IPv6.Error != "" {
				msg = res.IPv6.Error
			}
			h.writeRawText(w, r, http.StatusServiceUnavailable, msg)
			return
		}
		h.writeRawText(w, r, http.StatusOK, res.IPv6.IP)

	default:
		var lines []string
		if res.IPv4 != nil && res.IPv4.IP != "" {
			lines = append(lines, "ipv4: "+res.IPv4.IP)
		}
		if res.IPv6 != nil && res.IPv6.IP != "" {
			lines = append(lines, "ipv6: "+res.IPv6.IP)
		}
		if len(lines) == 0 {
			h.writeRawText(w, r, http.StatusServiceUnavailable, "no ip address available")
			return
		}
		h.writeRawText(w, r, http.StatusOK, strings.Join(lines, "\n"))
	}
}

func (h *ServerHandler) writeRawText(w http.ResponseWriter, r *http.Request, status int, body string) {
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	h.logAccess(r, status)
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
	h.logAccess(r, status)
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
	if h.logger != nil {
		h.logger.Printf("444 drop (%s) remote=%s method=%s path=%s query=%s",
			reason,
			extractClientIP(r, h.trustProxy),
			r.Method,
			r.URL.Path,
			redactQuery(r.URL.RawQuery),
		)
	}
	dropConn(w)
}

func (h *ServerHandler) logAccess(r *http.Request, status int) {
	if h.logger != nil {
		h.logger.Printf("%d remote=%s method=%s path=%s query=%s",
			status,
			extractClientIP(r, h.trustProxy),
			r.Method,
			r.URL.Path,
			redactQuery(r.URL.RawQuery),
		)
	}
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

func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, _, hasEq := strings.Cut(p, "=")
		if k == "token" && hasEq {
			parts[i] = "token=***"
		}
	}
	return strings.Join(parts, "&")
}

func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if addr, err := netip.ParseAddr(first); err == nil {
				return addr.String()
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if addr, err := netip.ParseAddr(xri); err == nil {
				return addr.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
