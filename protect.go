package pseudotcp

import (
	"fmt"
	"syscall"
)

// Protect overrides Android's VpnService.protect()
// Arguments:
// fileDescriptor is a system file descriptor to protect from the VPN
type SocketProtector func(fileDescriptor int) error

var (
	currentProtect SocketProtector
)

// Configure sets up a socket protect function to be usable as currentProtect
func ConfigureProtect(protect SocketProtector) {
	currentProtect = protect
}

func dialerControlProtect(prot SocketProtector) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		err := c.Control(func(fd uintptr) {
			if prot != nil {
				logger.Debug("Protecting FD", "fd", fd)
				if err := prot(int(fd)); err != nil {
					logger.Error("Error calling  prot", "err", err, "fd", fd)
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4194304); err != nil {
					logger.Error("Error setting SO_RCVBUF", "err", err)
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4194304); err != nil {
					logger.Error("Error setting SO_SNDBUF", "err", err)
				}
			}
		})

		if err != nil {
			// TODO: handle possible errors in doing protect
			return fmt.Errorf("error calling c.Control: %w", err)
		}
		return nil
	}
}
