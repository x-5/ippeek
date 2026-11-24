//go:build linux

package main

import (
	"errors"
	"syscall"
)

func applyBindToDevice(fd int, ifaceName string) error {
	if bindToDeviceHook != nil {
		return bindToDeviceHook(fd, ifaceName)
	}
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
}

// makeDialerControl binds outbound sockets to the specified network interface on Linux.
// When hasLocalIP is true and the process lacks CAP_NET_RAW / root (EPERM/EACCES),
// it falls back to Dialer.LocalAddr binding.
// When hasLocalIP is false, EPERM/EACCES is never ignored so outbound probes cannot
// silently fall back to the host's default route.
func makeDialerControl(ifaceName string, hasLocalIP bool) (func(network, address string, c syscall.RawConn) error, error) {
	if ifaceName == "" {
		return nil, nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = applyBindToDevice(int(fd), ifaceName)
		}); err != nil {
			return err
		}
		if errors.Is(sockErr, syscall.EPERM) || errors.Is(sockErr, syscall.EACCES) {
			if hasLocalIP {
				return nil
			}
			return &netWrapError{
				msg: "interface " + ifaceName + ": " + ErrNoRoutableAddress.Error() + " (SO_BINDTODEVICE not permitted)",
				err: ErrNoRoutableAddress,
			}
		}
		return sockErr
	}, nil
}
