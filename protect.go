package pseudotcp

import (
	"fmt"
	"syscall"
)

// Configure sets up a socket protect function to be usable as currentProtect
func (t *PseudoTCP) ConfigureProtect(protect SocketProtector) {
	t.currentProtect = protect
}

func (t *PseudoTCP) dialerControlProtect() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		err := c.Control(func(fd uintptr) {
			if t.currentProtect != nil {
				t.logger.Debug("Protecting FD", "fd", fd)
				if err := t.currentProtect(int(fd)); err != nil {
					t.logger.Error("Error calling  prot", "err", err, "fd", fd)
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4194304); err != nil {
					t.logger.Error("Error setting SO_RCVBUF", "err", err)
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4194304); err != nil {
					t.logger.Error("Error setting SO_SNDBUF", "err", err)
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
