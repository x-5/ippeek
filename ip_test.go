package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type stubInterfaceProvider struct {
	ifaces []NetInterface
	err    error
}

func (s stubInterfaceProvider) List() ([]NetInterface, error) {
	return s.ifaces, s.err
}

type stubProber struct {
	v4Res     ProbeResult
	v4Err     error
	v6Res     ProbeResult
	v6Err     error
	v4Calls   atomic.Int32
	v6Calls   atomic.Int32
	lastIface string
	lastIP    net.IP
}

func (s *stubProber) Probe(_ context.Context, family IPFamily, ifaceName string, localIP net.IP, _ bool) (ProbeResult, error) {
	s.lastIface = ifaceName
	s.lastIP = localIP
	if family == FamilyV6 {
		s.v6Calls.Add(1)
		return s.v6Res, s.v6Err
	}
	s.v4Calls.Add(1)
	return s.v4Res, s.v4Err
}

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// Public IPv4
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"114.114.114.114", true},
		{"223.5.5.5", true},
		// Non-public IPv4
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},       // CGNAT start
		{"100.127.255.254", false},  // CGNAT end
		{"127.0.0.1", false},        // Loopback
		{"169.254.1.1", false},      // Link-local
		{"192.0.2.1", false},        // TEST-NET-1
		{"198.51.100.1", false},     // TEST-NET-2
		{"203.0.113.1", false},      // TEST-NET-3
		{"224.0.0.1", false},        // Multicast
		{"0.0.0.0", false},          // Unspecified
		// Public IPv6
		{"240e:3b1:1234::1", true},
		{"2606:4700:4700::1111", true},
		{"2400:3200::1", true},
		// Non-public IPv6
		{"::1", false},              // Loopback
		{"::", false},               // Unspecified
		{"fe80::1", false},          // Link-local
		{"fc00::1", false},          // ULA
		{"fd12:3456::1", false},     // ULA
		{"2001:db8::1", false},      // Documentation
		{"2001::1", false},          // Teredo
		{"100::1", false},           // Discard
		{"::ffff:8.8.8.8", false},   // IPv4-mapped IPv6
		{"ff02::1", false},          // Multicast
	}

	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		if got := IsPublicIP(addr); got != tc.want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestResolverSmartAuto(t *testing.T) {
	ifaces := []NetInterface{
		{
			Name:     "lo",
			Up:       true,
			Loopback: true,
			IPv4:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			IPv6:     []netip.Addr{netip.MustParseAddr("::1")},
		},
		{
			Name: "docker0",
			Up:   true,
			IPv4: []netip.Addr{netip.MustParseAddr("172.17.0.1")},
		},
		{
			Name: "eth0",
			Up:   true,
			MAC:  "aa:bb:cc:dd:ee:ff",
			IPv4: []netip.Addr{netip.MustParseAddr("100.64.10.2")}, // CGNAT -> must fall back to external
			IPv6: []netip.Addr{
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("240e:3b1:1234::1"), // Public IPv6 -> must come directly from NIC
			},
		},
	}

	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
		v6Res: ProbeResult{IP: "240e:ffff::1", Probe: "http://6.ipw.cn"},
	}

	r := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)
	out, err := r.Resolve(context.Background(), ResolveOptions{
		Version: "all",
		Source:  SourceAuto,
	})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if out.IPv4 == nil || out.IPv4.IP != "1.2.3.4" || out.IPv4.Source != "external" {
		t.Fatalf("unexpected IPv4 result: %+v", out.IPv4)
	}
	if out.IPv6 == nil || out.IPv6.IP != "240e:3b1:1234::1" || out.IPv6.Source != "interface" || out.IPv6.Iface != "eth0" {
		t.Fatalf("unexpected IPv6 result: %+v", out.IPv6)
	}
	if prober.v4Calls.Load() != 1 {
		t.Fatalf("expected 1 external v4 probe call, got %d", prober.v4Calls.Load())
	}
	if prober.v6Calls.Load() != 0 {
		t.Fatalf("expected 0 external v6 probe calls (NIC hit), got %d", prober.v6Calls.Load())
	}
	// Loopback must be excluded from default overview interfaces, physical eth0 ranked before docker0.
	if len(out.Interfaces) != 2 || out.Interfaces[0].Name != "eth0" || out.Interfaces[1].Name != "docker0" {
		t.Fatalf("unexpected interfaces ordering: %+v", out.Interfaces)
	}
}

func TestResolverLocalAndExternalAndNotFound(t *testing.T) {
	ifaces := []NetInterface{
		{
			Name: "eth0",
			Up:   true,
			IPv4: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			IPv6: []netip.Addr{netip.MustParseAddr("240e:3b1:1234::1")},
		},
	}
	prober := &stubProber{
		v4Res: ProbeResult{IP: "1.2.3.4", Probe: "http://4.ipw.cn"},
		v6Res: ProbeResult{IP: "240e:3b1:1234::1", Probe: "http://6.ipw.cn"},
	}
	r := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)

	// source=local returns private IPv4 directly with 0 external calls.
	localOut, err := r.Resolve(context.Background(), ResolveOptions{
		Version: "4",
		Iface:   "eth0",
		Source:  SourceLocal,
	})
	if err != nil {
		t.Fatalf("local resolve failed: %v", err)
	}
	if localOut.IPv4 == nil || localOut.IPv4.IP != "192.168.1.10" || localOut.IPv4.Source != "interface" {
		t.Fatalf("unexpected local IPv4: %+v", localOut.IPv4)
	}
	if prober.v4Calls.Load() != 0 {
		t.Fatalf("expected 0 external calls in local mode, got %d", prober.v4Calls.Load())
	}

	// source=external forces external probe even when NIC has public IPv6, passing iface + localIP.
	extOut, err := r.Resolve(context.Background(), ResolveOptions{
		Version: "6",
		Iface:   "eth0",
		Source:  SourceExternal,
	})
	if err != nil {
		t.Fatalf("external resolve failed: %v", err)
	}
	if extOut.IPv6 == nil || extOut.IPv6.Source != "external" {
		t.Fatalf("unexpected external IPv6: %+v", extOut.IPv6)
	}
	if prober.lastIface != "eth0" || prober.lastIP.String() != "240e:3b1:1234::1" {
		t.Fatalf("expected iface=eth0 localIP=240e:3b1:1234::1, got iface=%q localIP=%v", prober.lastIface, prober.lastIP)
	}

	// Unknown interface returns ErrInterfaceNotFound.
	_, err = r.Resolve(context.Background(), ResolveOptions{
		Version: "4",
		Iface:   "nonexistent0",
		Source:  SourceAuto,
	})
	if !errors.Is(err, ErrInterfaceNotFound) {
		t.Fatalf("expected ErrInterfaceNotFound, got %v", err)
	}
}

func TestResolverStrictIfaceNoDefaultRouteLeak(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("203.0.114.10"))
	}))
	defer srv.Close()

	origHook := bindToDeviceHook
	bindToDeviceHook = func(fd int, ifaceName string) error {
		return syscall.EPERM
	}
	defer func() { bindToDeviceHook = origHook }()

	ifaces := []NetInterface{
		{
			Name: "eth0",
			Up:   true,
			IPv4: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
		},
		{
			Name: "eth1",
			Up:   true,
			// Only link-local IPv4: no routable IPv4 address.
			IPv4: []netip.Addr{netip.MustParseAddr("169.254.10.20")},
		},
	}

	prober := NewProber([]string{srv.URL}, nil, 2*time.Second, 0)
	r := NewResolver(stubInterfaceProvider{ifaces: ifaces}, prober)

	out, err := r.Resolve(context.Background(), ResolveOptions{
		Version: "4",
		Iface:   "eth1",
		Source:  SourceAuto,
	})
	if err != nil {
		t.Fatalf("Resolve returned unexpected top-level error: %v", err)
	}
	if out.IPv4 == nil || out.IPv4.IP != "" || !strings.Contains(out.IPv4.Error, ErrNoRoutableAddress.Error()) {
		t.Fatalf("expected ErrNoRoutableAddress error in IPv4 result, got %+v", out.IPv4)
	}
	if hits.Load() != 0 {
		t.Fatalf("expected 0 upstream hits (no default-route leak), got %d", hits.Load())
	}
}

func TestParseProcIfInet6(t *testing.T) {
	sample := strings.Join([]string{
		"00000000000000000000000000000001 01 80 10 80       lo",
		"240e03b1123400000000000000000001 02 40 00 20     eth0",
		"240e03b112340000aabbccddeeff0011 02 40 00 01     eth0",
		"240e03b1123400000000000000000002 02 40 00 00     eth0",
		"240E03B1123400000000000000000003 02 40 00 21     eth0",
		"short line",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 02 40 00 00     eth0",
		"240e03b1123400000000000000000004 02 40 00 zz     eth0",
		"",
	}, "\n")

	got := parseProcIfInet6(sample)
	if len(got) != 2 {
		t.Fatalf("expected 2 interfaces, got %d: %+v", len(got), got)
	}
	if f := got["lo"][netip.MustParseAddr("::1")]; f != 0x80 {
		t.Fatalf("expected lo ::1 flags=0x80, got 0x%x", f)
	}
	eth0 := got["eth0"]
	if len(eth0) != 4 {
		t.Fatalf("expected 4 valid eth0 entries, got %d: %+v", len(eth0), eth0)
	}
	if f := eth0[netip.MustParseAddr("240e:3b1:1234::1")]; f != ifaFlagDeprecated {
		t.Fatalf("expected deprecated flag 0x20, got 0x%x", f)
	}
	if f := eth0[netip.MustParseAddr("240e:3b1:1234:0:aabb:ccdd:eeff:11")]; f != ifaFlagTemporary {
		t.Fatalf("expected temporary flag 0x01, got 0x%x", f)
	}
	if f := eth0[netip.MustParseAddr("240e:3b1:1234::2")]; f != 0x00 {
		t.Fatalf("expected stable flag 0x00, got 0x%x", f)
	}
	if f := eth0[netip.MustParseAddr("240e:3b1:1234::3")]; f != (ifaFlagDeprecated | ifaFlagTemporary) {
		t.Fatalf("expected deprecated|temporary 0x21, got 0x%x", f)
	}
}

func TestIPv6AddressPriority(t *testing.T) {
	depPub := netip.MustParseAddr("240e:3b1:1234::1")
	tempPub := netip.MustParseAddr("240e:3b1:1234::abcd:ef01")
	stablePub := netip.MustParseAddr("240e:3b1:1234::2")
	ula := netip.MustParseAddr("fd12:3456::10")

	t.Run("prefer_stable_over_temporary_and_skip_deprecated", func(t *testing.T) {
		iface := NetInterface{
			Name: "eth0",
			Up:   true,
			IPv6: []netip.Addr{depPub, tempPub, stablePub},
			ipv6Flags: map[netip.Addr]uint32{
				depPub:    ifaFlagDeprecated,
				tempPub:   ifaFlagTemporary,
				stablePub: 0x00,
			},
		}
		prober := &stubProber{v6Res: ProbeResult{IP: "240e:ffff::1", Probe: "http://6.ipw.cn"}}
		r := NewResolver(stubInterfaceProvider{ifaces: []NetInterface{iface}}, prober)

		autoOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Source: SourceAuto})
		if err != nil || autoOut.IPv6 == nil || autoOut.IPv6.IP != stablePub.String() || autoOut.IPv6.Source != "interface" {
			t.Fatalf("auto mode expected stable %s, got %+v err=%v", stablePub, autoOut.IPv6, err)
		}

		localOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Iface: "eth0", Source: SourceLocal})
		if err != nil || localOut.IPv6 == nil || localOut.IPv6.IP != stablePub.String() {
			t.Fatalf("local mode expected stable %s, got %+v err=%v", stablePub, localOut.IPv6, err)
		}

		if outIP := pickOutboundLocalIP(iface, FamilyV6); outIP == nil || outIP.String() != stablePub.String() {
			t.Fatalf("pickOutboundLocalIP expected %s, got %v", stablePub, outIP)
		}
	})

	t.Run("use_temporary_when_no_stable_public", func(t *testing.T) {
		iface := NetInterface{
			Name: "eth0",
			Up:   true,
			IPv6: []netip.Addr{depPub, tempPub},
			ipv6Flags: map[netip.Addr]uint32{
				depPub:  ifaFlagDeprecated,
				tempPub: ifaFlagTemporary,
			},
		}
		r := NewResolver(stubInterfaceProvider{ifaces: []NetInterface{iface}}, &stubProber{})

		autoOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Source: SourceAuto})
		if err != nil || autoOut.IPv6 == nil || autoOut.IPv6.IP != tempPub.String() || autoOut.IPv6.Source != "interface" {
			t.Fatalf("auto mode expected temporary %s, got %+v err=%v", tempPub, autoOut.IPv6, err)
		}
	})

	t.Run("skip_deprecated_in_auto_and_local", func(t *testing.T) {
		iface := NetInterface{
			Name: "eth0",
			Up:   true,
			IPv6: []netip.Addr{depPub, ula},
			ipv6Flags: map[netip.Addr]uint32{
				depPub: ifaFlagDeprecated,
				ula:    0x00,
			},
		}
		prober := &stubProber{v6Res: ProbeResult{IP: "240e:9999::1", Probe: "http://6.ipw.cn"}}
		r := NewResolver(stubInterfaceProvider{ifaces: []NetInterface{iface}}, prober)

		// Auto mode must skip deprecated public IPv6 and fall back to external prober.
		autoOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Source: SourceAuto})
		if err != nil || autoOut.IPv6 == nil || autoOut.IPv6.IP != "240e:9999::1" || autoOut.IPv6.Source != "external" {
			t.Fatalf("auto mode expected external fallback, got %+v err=%v", autoOut.IPv6, err)
		}
		if prober.v6Calls.Load() != 1 {
			t.Fatalf("expected 1 external v6 probe call, got %d", prober.v6Calls.Load())
		}

		// Local mode must skip deprecated public IPv6 and select non-deprecated ULA.
		localOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Iface: "eth0", Source: SourceLocal})
		if err != nil || localOut.IPv6 == nil || localOut.IPv6.IP != ula.String() {
			t.Fatalf("local mode expected non-deprecated ULA %s, got %+v err=%v", ula, localOut.IPv6, err)
		}

		// Outbound local IP must also skip deprecated public IPv6 and pick ULA.
		if outIP := pickOutboundLocalIP(iface, FamilyV6); outIP == nil || outIP.String() != ula.String() {
			t.Fatalf("pickOutboundLocalIP expected %s, got %v", ula, outIP)
		}
	})

	t.Run("only_deprecated_returns_no_local_ipv6", func(t *testing.T) {
		iface := NetInterface{
			Name: "eth0",
			Up:   true,
			IPv6: []netip.Addr{depPub},
			ipv6Flags: map[netip.Addr]uint32{
				depPub: ifaFlagDeprecated,
			},
		}
		r := NewResolver(stubInterfaceProvider{ifaces: []NetInterface{iface}}, &stubProber{})

		localOut, err := r.Resolve(context.Background(), ResolveOptions{Version: "6", Iface: "eth0", Source: SourceLocal})
		if err != nil || localOut.IPv6 == nil || localOut.IPv6.IP != "" || localOut.IPv6.Error == "" {
			t.Fatalf("expected error when only deprecated IPv6 exists, got %+v err=%v", localOut.IPv6, err)
		}
		if outIP := pickOutboundLocalIP(iface, FamilyV6); outIP != nil {
			t.Fatalf("expected nil outbound IP when only deprecated IPv6 exists, got %v", outIP)
		}
	})
}
