//go:build !tiny

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
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

	netType := family.network()
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, netType, addr)
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   p.timeout,
		ResponseHeaderTimeout: p.timeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	var lastErr error
	for _, probeURL := range probes {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		ipStr, err := probeOneStd(ctx, client, family, probeURL)
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

func probeOneStd(ctx context.Context, client *http.Client, family IPFamily, probeURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ippeek/1.0")
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("unexpected HTTP status " + strconv.Itoa(resp.StatusCode))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}

	return parseProbeIP(raw, family)
}
