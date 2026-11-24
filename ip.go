package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Linux IPv6 IFA_F_* address flags parsed from /proc/net/if_inet6.
const (
	ifaFlagTemporary  uint32 = 0x01 // IFA_F_TEMPORARY / IFA_F_SECONDARY
	ifaFlagDeprecated uint32 = 0x20 // IFA_F_DEPRECATED
)

// ErrInterfaceNotFound is returned when the requested network interface does not exist.
var ErrInterfaceNotFound = errors.New("network interface not found")

// ErrNoRoutableAddress is returned when an explicit interface cannot be bound for outbound probing.
var ErrNoRoutableAddress = errors.New("interface has no routable address")

type netWrapError struct {
	msg string
	err error
}

func (e *netWrapError) Error() string {
	return e.msg
}

func (e *netWrapError) Unwrap() error {
	return e.err
}

// SourceMode controls how an IP address is resolved.
type SourceMode string

const (
	SourceAuto     SourceMode = "auto"
	SourceLocal    SourceMode = "local"
	SourceExternal SourceMode = "external"
)

// InterfaceInfo is the JSON representation of a local network interface.
type InterfaceInfo struct {
	Name string   `json:"name"`
	Up   bool     `json:"up"`
	MAC  string   `json:"mac,omitempty"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// IPResult represents the resolved IPv4 or IPv6 entry.
type IPResult struct {
	IP     string `json:"ip,omitempty"`
	Source string `json:"source,omitempty"`
	Iface  string `json:"iface,omitempty"`
	Probe  string `json:"probe,omitempty"`
	Cached bool   `json:"cached,omitempty"`
	Error  string `json:"error,omitempty"`
}

// OverviewResponse is the full JSON payload returned when format=json.
type OverviewResponse struct {
	Version    string          `json:"version,omitempty"`
	IPv4       *IPResult       `json:"ipv4,omitempty"`
	IPv6       *IPResult       `json:"ipv6,omitempty"`
	Interfaces []InterfaceInfo `json:"interfaces,omitempty"`
	ClientIP   string          `json:"client_ip,omitempty"`
	Hostname   string          `json:"hostname,omitempty"`
	Timestamp  string          `json:"timestamp"`
}

// NetInterface is the normalized internal representation of a host network interface.
type NetInterface struct {
	Name      string
	Up        bool
	Loopback  bool
	MAC       string
	IPv4      []netip.Addr
	IPv6      []netip.Addr
	ipv6Flags map[netip.Addr]uint32
}

// InterfaceProvider abstracts host network interface enumeration for testability.
type InterfaceProvider interface {
	List() ([]NetInterface, error)
}

// OSInterfaceProvider enumerates host network interfaces via the Go standard library.
type OSInterfaceProvider struct{}

// List returns all interfaces reported by the operating system.
func (OSInterfaceProvider) List() ([]NetInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ipv6FlagsByIface := readIPv6AddrFlags()

	out := make([]NetInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		ni := NetInterface{
			Name:      iface.Name,
			Up:        iface.Flags&net.FlagUp != 0,
			Loopback:  iface.Flags&net.FlagLoopback != 0,
			MAC:       iface.HardwareAddr.String(),
			ipv6Flags: ipv6FlagsByIface[iface.Name],
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, raw := range addrs {
				var ip net.IP
				switch v := raw.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				default:
					continue
				}
				if ip == nil {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					if addr, ok := netip.AddrFromSlice(ip4); ok {
						ni.IPv4 = append(ni.IPv4, addr)
					}
					continue
				}
				if ip16 := ip.To16(); ip16 != nil {
					if addr, ok := netip.AddrFromSlice(ip16); ok && addr.Is6() && !addr.Is4In6() {
						ni.IPv6 = append(ni.IPv6, addr)
					}
				}
			}
		}

		out = append(out, ni)
	}

	return out, nil
}

// nonPublicPrefixes lists reserved ranges not covered by netip.Addr.IsPrivate().
var nonPublicPrefixes = []netip.Prefix{
	// IPv4 reserved / non-globally-routable ranges
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT (carrier NAT / Tailscale)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF Protocol Assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved for future use
	// IPv6 reserved / non-globally-routable ranges
	netip.MustParsePrefix("100::/64"),      // Discard-Only
	netip.MustParsePrefix("2001:db8::/32"), // Documentation
	netip.MustParsePrefix("2001:2::/48"),   // Benchmarking
	netip.MustParsePrefix("2001::/32"),     // Teredo
}

// IsPublicIP reports whether addr is a globally routable public IPv4 or IPv6 unicast address.
func IsPublicIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Is4In6() {
		return false
	}
	if !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var virtualIfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "cni", "flannel", "podman",
	"kube", "cali", "cilium", "tun", "tap", "utun", "tailscale", "wg", "zt",
}

func isVirtualIface(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ResolveOptions specifies parameters for IP resolution.
type ResolveOptions struct {
	Version string // "4", "6", or "all"
	Iface   string
	Source  SourceMode
	Refresh bool
}

// ResolveOutput holds resolved IPv4/IPv6 results and interface metadata.
type ResolveOutput struct {
	IPv4       *IPResult
	IPv6       *IPResult
	Interfaces []InterfaceInfo
}

// Resolver combines local NIC inspection with external probing.
type Resolver struct {
	ifaces InterfaceProvider
	prober ExternalProber
}

// NewResolver constructs a Resolver.
func NewResolver(ifaces InterfaceProvider, prober ExternalProber) *Resolver {
	return &Resolver{
		ifaces: ifaces,
		prober: prober,
	}
}

// Resolve computes the requested IPv4/IPv6 addresses and interface overview.
func (r *Resolver) Resolve(ctx context.Context, opts ResolveOptions) (ResolveOutput, error) {
	allIfaces, err := r.ifaces.List()
	if err != nil {
		return ResolveOutput{}, &netWrapError{
			msg: "list interfaces: " + err.Error(),
			err: err,
		}
	}

	var candidates []NetInterface
	var targetIface *NetInterface

	if opts.Iface != "" {
		for i := range allIfaces {
			if allIfaces[i].Name == opts.Iface {
				found := allIfaces[i]
				targetIface = &found
				candidates = []NetInterface{found}
				break
			}
		}
		if targetIface == nil {
			return ResolveOutput{}, ErrInterfaceNotFound
		}
	} else {
		candidates = sortCandidates(allIfaces)
	}

	out := ResolveOutput{
		Interfaces: toInterfaceInfos(candidates, opts.Iface != ""),
	}

	wantV4 := opts.Version == "4" || opts.Version == "all"
	wantV6 := opts.Version == "6" || opts.Version == "all"

	if wantV4 && wantV6 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			res := r.resolveFamily(ctx, FamilyV4, opts, candidates, targetIface)
			out.IPv4 = &res
		}()
		go func() {
			defer wg.Done()
			res := r.resolveFamily(ctx, FamilyV6, opts, candidates, targetIface)
			out.IPv6 = &res
		}()
		wg.Wait()
	} else if wantV4 {
		res := r.resolveFamily(ctx, FamilyV4, opts, candidates, targetIface)
		out.IPv4 = &res
	} else if wantV6 {
		res := r.resolveFamily(ctx, FamilyV6, opts, candidates, targetIface)
		out.IPv6 = &res
	}

	return out, nil
}

func (r *Resolver) resolveFamily(
	ctx context.Context,
	family IPFamily,
	opts ResolveOptions,
	candidates []NetInterface,
	targetIface *NetInterface,
) IPResult {
	switch opts.Source {
	case SourceLocal:
		if addr, ifaceName, ok := findInterfaceIP(candidates, family, false, opts.Iface != ""); ok {
			return IPResult{
				IP:     addr.String(),
				Source: "interface",
				Iface:  ifaceName,
			}
		}
		return IPResult{
			Iface: opts.Iface,
			Error: "no local " + family.String() + " address available",
		}

	case SourceAuto:
		if addr, ifaceName, ok := findInterfaceIP(candidates, family, true, opts.Iface != ""); ok {
			return IPResult{
				IP:     addr.String(),
				Source: "interface",
				Iface:  ifaceName,
			}
		}
		return r.probeExternal(ctx, family, opts, targetIface)

	case SourceExternal:
		return r.probeExternal(ctx, family, opts, targetIface)

	default:
		return IPResult{Error: "unsupported source mode"}
	}
}

func (r *Resolver) probeExternal(
	ctx context.Context,
	family IPFamily,
	opts ResolveOptions,
	targetIface *NetInterface,
) IPResult {
	if r.prober == nil {
		return IPResult{
			Iface: opts.Iface,
			Error: "external " + family.String() + " prober not configured",
		}
	}

	var localIP net.IP
	if targetIface != nil {
		localIP = pickOutboundLocalIP(*targetIface, family)
	}

	res, err := r.prober.Probe(ctx, family, opts.Iface, localIP, opts.Refresh)
	if err != nil {
		return IPResult{
			Iface: opts.Iface,
			Error: err.Error(),
		}
	}

	return IPResult{
		IP:     res.IP,
		Source: "external",
		Iface:  opts.Iface,
		Probe:  res.Probe,
		Cached: res.Cached,
	}
}

func sortCandidates(ifaces []NetInterface) []NetInterface {
	out := make([]NetInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Loopback {
			continue
		}
		out = append(out, iface)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri := ifaceRank(out[i])
		rj := ifaceRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func ifaceRank(iface NetInterface) int {
	if !iface.Up {
		return 2
	}
	if isVirtualIface(iface.Name) {
		return 1
	}
	return 0
}

func findInterfaceIP(candidates []NetInterface, family IPFamily, publicOnly bool, explicitIface bool) (netip.Addr, string, bool) {
	for _, iface := range candidates {
		if !explicitIface && (!iface.Up || iface.Loopback) {
			continue
		}
		addrs := iface.IPv4
		var flags map[netip.Addr]uint32
		if family == FamilyV6 {
			addrs = iface.IPv6
			flags = iface.ipv6Flags
		}
		if addr, ok := pickAddr(addrs, flags, publicOnly); ok {
			return addr, iface.Name, true
		}
	}
	return netip.Addr{}, "", false
}

func pickAddr(addrs []netip.Addr, flags map[netip.Addr]uint32, publicOnly bool) (netip.Addr, bool) {
	if len(addrs) == 0 {
		return netip.Addr{}, false
	}
	if publicOnly {
		var tempFallback netip.Addr
		for _, a := range addrs {
			if !IsPublicIP(a) {
				continue
			}
			f := flags[a]
			if f&ifaFlagDeprecated != 0 {
				continue
			}
			if f&ifaFlagTemporary == 0 {
				return a, true
			}
			if !tempFallback.IsValid() {
				tempFallback = a
			}
		}
		if tempFallback.IsValid() {
			return tempFallback, true
		}
		return netip.Addr{}, false
	}

	// Local mode preference: non-deprecated public (stable > temporary) >
	// non-link-local unicast (stable > temporary) > loopback > link-local.
	bestScore := -1
	var best netip.Addr
	for _, a := range addrs {
		score := localAddrScore(a, flags[a])
		if score > bestScore {
			bestScore = score
			best = a
		}
	}
	if bestScore < 0 {
		return netip.Addr{}, false
	}
	return best, true
}

func localAddrScore(a netip.Addr, flag uint32) int {
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || flag&ifaFlagDeprecated != 0 {
		return -1
	}
	if IsPublicIP(a) {
		if flag&ifaFlagTemporary == 0 {
			return 6
		}
		return 5
	}
	if a.IsGlobalUnicast() {
		if flag&ifaFlagTemporary == 0 {
			return 4
		}
		return 3
	}
	if a.IsLoopback() {
		return 2
	}
	if a.IsLinkLocalUnicast() {
		return 1
	}
	return 0
}

func pickOutboundLocalIP(iface NetInterface, family IPFamily) net.IP {
	addrs := iface.IPv4
	var flags map[netip.Addr]uint32
	if family == FamilyV6 {
		addrs = iface.IPv6
		flags = iface.ipv6Flags
	}

	bestScore := -1
	var best netip.Addr
	for _, a := range addrs {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() {
			continue
		}
		f := flags[a]
		if f&ifaFlagDeprecated != 0 {
			continue
		}
		score := -1
		if IsPublicIP(a) {
			if f&ifaFlagTemporary == 0 {
				score = 4
			} else {
				score = 3
			}
		} else if a.IsGlobalUnicast() {
			if f&ifaFlagTemporary == 0 {
				score = 2
			} else {
				score = 1
			}
		}
		if score > bestScore {
			bestScore = score
			best = a
		}
	}
	if bestScore >= 0 && best.IsValid() {
		return net.IP(best.AsSlice())
	}
	return nil
}

// parseProcIfInet6 parses Linux /proc/net/if_inet6 content into a per-interface map
// of IPv6 address -> IFA_F_* flags.
func parseProcIfInet6(content string) map[string]map[netip.Addr]uint32 {
	var out map[string]map[netip.Addr]uint32
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		addrHex := fields[0]
		if len(addrHex) != 32 {
			continue
		}
		var b [16]byte
		validHex := true
		for i := 0; i < 16; i++ {
			v, ok := parseHexByte(addrHex[i*2], addrHex[i*2+1])
			if !ok {
				validHex = false
				break
			}
			b[i] = v
		}
		if !validHex {
			continue
		}
		flagVal, err := strconv.ParseUint(fields[4], 16, 32)
		if err != nil {
			continue
		}
		addr := netip.AddrFrom16(b)
		ifname := fields[5]
		if out == nil {
			out = make(map[string]map[netip.Addr]uint32)
		}
		if out[ifname] == nil {
			out[ifname] = make(map[netip.Addr]uint32)
		}
		out[ifname][addr] = uint32(flagVal)
	}
	return out
}

func parseHexByte(hi, lo byte) (byte, bool) {
	h, ok1 := parseHexNibble(hi)
	l, ok2 := parseHexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return (h << 4) | l, true
}

func parseHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func toInterfaceInfos(candidates []NetInterface, explicit bool) []InterfaceInfo {
	infos := make([]InterfaceInfo, 0, len(candidates))
	for _, c := range candidates {
		if !explicit && c.Loopback {
			continue
		}
		info := InterfaceInfo{
			Name: c.Name,
			Up:   c.Up,
			MAC:  c.MAC,
		}
		for _, a := range c.IPv4 {
			info.IPv4 = append(info.IPv4, a.String())
		}
		for _, a := range c.IPv6 {
			info.IPv6 = append(info.IPv6, a.String())
		}
		infos = append(infos, info)
	}
	return infos
}
