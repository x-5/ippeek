//go:build !linux

package main

import "syscall"

// makeDialerControl enforces strict interface binding on non-Linux platforms where
// SO_BINDTODEVICE is unavailable: if an explicit interface has no local IP to bind,
// return ErrNoRoutableAddress instead of silently falling back to the default route.
func makeDialerControl(ifaceName string, hasLocalIP bool) (func(network, address string, c syscall.RawConn) error, error) {
	if ifaceName != "" && !hasLocalIP {
		return nil, &netWrapError{
			msg: "interface " + ifaceName + ": " + ErrNoRoutableAddress.Error(),
			err: ErrNoRoutableAddress,
		}
	}
	return nil, nil
}
