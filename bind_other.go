//go:build !linux

package main

import "syscall"

// makeDialerControl returns nil on non-Linux platforms where interface selection relies on Dialer.LocalAddr.
func makeDialerControl(ifaceName string) func(network, address string, c syscall.RawConn) error {
	return nil
}
