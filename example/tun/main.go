package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	masqueH2 "github.com/invisv-privacy/masque/http2"
	"github.com/invisv-privacy/pseudotcp"
	"github.com/invisv-privacy/pseudotcp/internal/testutils"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func main() {
	verbose := flag.Bool("verbose", true, "Whether to log at DEBUG level")

	ifaceAddr := flag.String("ifaceAddr", "10.99.99.10/24", "An address with subnet that won't conflict with any other on the local machine")

	proxyAddr := flag.String("proxyAddr", "", "The address IP or FQDN of the proxy running the MASQUE server")

	proxyPort := flag.String("proxyPort", "8444", "The port that the MASQUE server is running on")

	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	slog.SetDefault(logger)

	if *proxyAddr == "" {
		flag.Usage()
		log.Fatal("proxyAddr must be defined")
	}

	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatalf("Failed to create new TUN device: %v", err)
	}

	tun, err := netlink.LinkByName(iface.Name())
	if err != nil {
		log.Fatalf("Failed to get tun interface: %v", err)
	}

	addr, err := netlink.ParseAddr(*ifaceAddr)
	if err != nil {
		log.Fatalf("Failed to parse addr: %v", err)
	}

	if err := netlink.AddrAdd(tun, addr); err != nil {
		log.Fatalf("Failed to add address to tun device: %v", err)
	}

	if err := netlink.LinkSetUp(tun); err != nil {
		log.Fatalf("Failed to set tun interface up: %v", err)
	}

	logger.Info("TUN setup", "iface", iface)

	protectConnection := pseudotcp.SocketProtector(func(fd int) error {
		logger.Debug("Protecting", "fd", fd)
		return nil
	})

	sendPacket := func(packet []byte, length int) error {
		p := gopacket.NewPacket(packet[:], layers.LayerTypeIPv4, gopacket.Default)
		logger.Debug("Sending to TUN device", "p", p)

		n, err := iface.Write(packet)
		if err != nil {
			return fmt.Errorf("failed to write packet to tun interface: %w", err)
		}
		if n != length {
			return fmt.Errorf("bytes written did not match sendPacket argument length, n: %d, length: %d", n, length)
		}

		logger.Debug("Wrote bytes to interface", "n", n)
		return nil
	}

	config := masqueH2.ClientConfig{
		ProxyAddr:  *proxyAddr + ":" + *proxyPort,
		IgnoreCert: true,
		Logger:     logger,
		AuthToken:  "fake-token",
		Prot:       masqueH2.SocketProtector(protectConnection),
	}

	proxyClient := &testutils.ProxyClient{
		Client:  masqueH2.NewClient(config),
		ProxyIP: *proxyAddr,
	}

	pTCPConfig := &pseudotcp.PseudoTCPConfig{
		Logger:     logger,
		SendPacket: sendPacket,

		ProxyClient: proxyClient,

		// Our test sends to a non-publicly route-able IP
		ProhibitDisallowedIPPorts: false,
	}

	pTCP := pseudotcp.NewPseudoTCP(pTCPConfig)

	pTCP.ConfigureProtect(protectConnection)

	err = pTCP.Init()
	if err != nil {
		log.Fatalf("Failed to Init pseudotcp: %v", err)
	}

	packet := make([]byte, 2000)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatalf("Failed to read from TUN device: %v", err)
		}
		p := gopacket.NewPacket(packet[:n], layers.LayerTypeIPv4, gopacket.Default)
		logger.Debug("Received from TUN device", "p", p)

		pTCP.Send(packet[:n])
	}
}
