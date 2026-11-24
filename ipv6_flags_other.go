//go:build !linux

package main

import "net/netip"

// readIPv6AddrFlags returns nil on non-Linux platforms where /proc/net/if_inet6 is not available.
func readIPv6AddrFlags() map[string]map[netip.Addr]uint32 {
	return nil
}
