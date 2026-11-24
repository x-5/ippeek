//go:build linux

package main

import (
	"errors"
	"syscall"
)

// makeDialerControl binds outbound sockets to the specified network interface on Linux.
// If the process lacks CAP_NET_RAW / root permissions, it gracefully falls back to LocalAddr binding.
func makeDialerControl(ifaceName string) func(network, address string, c syscall.RawConn) error {
	if ifaceName == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
		}); err != nil {
			return err
		}
		if errors.Is(sockErr, syscall.EPERM) || errors.Is(sockErr, syscall.EACCES) {
			return nil
		}
		return sockErr
	}
}
