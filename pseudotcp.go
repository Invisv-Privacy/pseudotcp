package pseudotcp

import (
	"encoding/hex"
	"errors"
	"log"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SendPacket func(packet []byte, length int) error

// Protect overrides Android's VpnService.protect()
// Arguments:
// fileDescriptor is a system file descriptor to protect from the VPN
type SocketProtector func(fileDescriptor int) error

var (
	currentProtect SocketProtector
)

var toLinux SendPacket

// Configure sets up a socket protect function to be usable as currentProtect
func ConfigureProtect(protect SocketProtector) {
	currentProtect = protect
}

func Init(sendPacket SendPacket, proxyFQDN string) error {
	toLinux = sendPacket
	return UserStackInit(proxyFQDN)
}

func Send(packetData []byte) {
	UserStackIPProcessPacket(packetData)
}

// active indicates whether we can process packets.
var active bool

// UserStackInit initializes the userspace network stack module. This must be called before any other UserStack function.
func UserStackInit(proxyFQDN string) error {
	log.Println("starting")

	if toLinux == nil {
		return errors.New("toLinux is nil")
	}

	active = true
	return nil
}

// ReconnectToProxy indicates to the that it should try to connect to the proxy again.
// This is good to call upon detection that a network interface has come back up.
func ReconnectToProxy(proxyFQDN string) error {
	log.Println("reconnecting")
	active = true
	return nil
}

// UserStackIPProcessPacket processes an IPv4 packet and emits the generated reply to Linux and/or our tunnel
func UserStackIPProcessPacket(p []byte) {
	packet := gopacket.NewPacket(p[:], layers.LayerTypeIPv4, gopacket.Default)
	log.Println("received packet", packet)
	log.Println(hex.Dump(p), "\n")
	return
}

// pseudoSendToLinux sends a packet to Android/Linux.
func pseudoSendToLinux(p []byte) error {
	packet := gopacket.NewPacket(p[:], layers.LayerTypeIPv4, gopacket.Default)
	log.Println("sending a packet to Linux", packet)
	log.Println(hex.Dump(p), "\n")
	if !active {
		return errors.New("not active")
	}

	err := toLinux(p, len(p))
	if err != nil {
		log.Println("Error sending packet to Linux:", err)
		return err
	}

	return nil
}

func dialerControlProtect(prot SocketProtector) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		c.Control(func(fd uintptr) {
			if prot != nil {
				log.Printf("Protecting FD %v", fd)
				prot(int(fd))
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4194304)
				if err != nil {
					log.Printf("Error setting SO_RCVBUF: %v", err)
				}
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4194304)
				if err != nil {
					log.Printf("Error setting SO_SNDBUF: %v", err)
				}
			}
		})
		return nil // TODO: handle possible errors in doing protect
	}
}
