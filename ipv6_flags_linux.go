//go:build linux

package main

import (
	"net/netip"
	"os"
)

// readIPv6AddrFlags reads /proc/net/if_inet6 on Linux and returns per-interface
// IPv6 address IFA_F_* flags. Returns nil if /proc/net/if_inet6 is unavailable.
func readIPv6AddrFlags() map[string]map[netip.Addr]uint32 {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	return parseProcIfInet6(string(data))
}
