package pseudotcp

import (
	"encoding/hex"
	"errors"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SendPacket func(packet []byte, length int) error

// Protect overrides Android's VpnService.protect()
// Arguments:
// fileDescriptor is a system file descriptor to protect from the VPN
type SocketProtector func(fileDescriptor int) error

var (
	CurrentProtect SocketProtector
)

var toLinux SendPacket

// Configure sets up a socket protect function to be usable as CurrentProtect
func ConfigureProtect(protect SocketProtector) {
	CurrentProtect = protect
}

func Init(sendPacket SendPacket, proxyFQDN string) error {
	toLinux = sendPacket
	return UserStackInit(proxyFQDN)
}

func Send(packetData []byte) {
	UserStackIPProcessPacket(packetData)
}

// UserStackInit initializes the userspace network stack module. This must be called before any other UserStack function.
func UserStackInit(proxyFQDN string) error {
	log.Println("starting")

	if toLinux == nil {
		return errors.New("toLinux is nil")
	}

	return nil
}

// ReconnectToProxy indicates to the that it should try to connect to the proxy again.
// This is good to call upon detection that a network interface has come back up.
func ReconnectToProxy(proxyFQDN string) error {
	log.Println("reconnecting")
	return nil
}

// UserStackIPProcessPacket processes an IPv4 packet and emits the generated reply to Linux and/or our tunnel
func UserStackIPProcessPacket(p []byte) {
	packet := gopacket.NewPacket(p[:], layers.LayerTypeIPv4, gopacket.Default)
	log.Println("received packet", packet)
	log.Println(hex.Dump(p))
}
