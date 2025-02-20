package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/invisv-privacy/pseudotcp"
	"github.com/invisv-privacy/pseudotcp/internal/testutils"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

var pTCP *pseudotcp.PseudoTCP

var netstack *stack.Stack
var endpointIP tcpip.Address

const h2oServiceName string = "h2o"

var sendPacket func(packet []byte, length int) error

var containerGateway string
var containerIP string

var logger *slog.Logger

var nicID tcpip.NICID = 1

func TestMain(m *testing.M) {
	level := slog.LevelDebug
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Start the h2o docker container
	identifier := tc.StackIdentifier("h2o_test")
	composeFile := fmt.Sprintf("%s/docker-compose.yml", testutils.RootDir())
	compose, err := tc.NewDockerComposeWith(tc.WithStackFiles(composeFile), identifier)
	if err != nil {
		log.Fatalf("error in NewDockerComposeAPIWith: %v", err)
	}

	defer func() {
		if err := compose.Down(
			context.Background(),
			tc.RemoveOrphans(true),
			tc.RemoveImagesLocal,
		); err != nil {
			log.Fatalf("error in compose.Down: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	composeStack := compose.WaitForService(h2oServiceName,
		// The h2o conf provides a /status endpoint listening on
		// non-TLS port 8081
		wait.
			NewHTTPStrategy("/status").
			WithPort("8081/tcp").
			WithStartupTimeout(10*time.Second),
	)

	if err := composeStack.Up(ctx, tc.Wait(true)); err != nil {
		log.Fatalf("error in compose.Up(): %v", err)
	}

	container, err := composeStack.ServiceContainer(ctx, h2oServiceName)
	if err != nil {
		log.Fatalf("error in composeStack.ServiceContainer: %v", err)
	}

	logger.Info("compose up", "services", composeStack.Services(), "container", container)

	// Kind of awkward network info parsing here.
	// We need the container's gateway IP because that _should_ be the address the host can ListenUDP on where the container can access it.
	containerIPs, err := container.ContainerIPs(ctx)
	if err != nil {
		log.Fatalf("error in container.ContainerIPs: %v", err)
	}

	containerIP = containerIPs[0]
	containerIPSplit := strings.Split(containerIP, ".")
	containerNet := strings.Join(containerIPSplit[:len(containerIPSplit)-1], ".")

	containerGateway = fmt.Sprintf("%v.1", containerNet)

	chanBufferLength := 1000

	// We need 2 channels, one where we can put packets coming from pseudotcp destined for our netstack and the other in the opposite direction
	var pseudoToNetstackChan = make(chan []byte, chanBufferLength)
	var netstackToPseudoChan = make(chan []byte, chanBufferLength)

	// Create the network Stack
	endpointIP = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	gatewayIP := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	netstack = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	defer netstack.Close()

	// Create the network interface
	linkEP := channel.New(128, 1024, "")
	defer linkEP.Close()

	tcpErr := netstack.CreateNIC(nicID, linkEP)
	if tcpErr != nil {
		log.Fatalf("failed to createNIC: %v", tcpErr)
	}

	tcpErr = netstack.SetNICMTU(nicID, pseudotcp.TUN_MTU)
	if tcpErr != nil {
		log.Fatalf("failed to SetNICMTU: %v", tcpErr)
	}

	// Read from the netstack link and send appropriate packets to pseudotcp
	go func() {
		for {
			pkt := linkEP.ReadContext(context.Background())
			logger.Debug("Read Packet from linkEP", "pkt", pkt)
			if pkt == nil {
				break
			} else if pkt.PktType == tcpip.PacketOutgoing {
				b := pkt.ToBuffer()
				pkt.DecRef()

				buf := make([]byte, b.Size())
				_, err := b.ReadAt(buf, 0)

				// EOF is the only acceptable "error" here
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Fatalf("recieved non-EOF error: %v", err)
					}
				}

				packet := gopacket.NewPacket(buf[:], layers.LayerTypeIPv4, gopacket.Default)

				logger.Debug("Sending to netstackToPseudoChan", "packet", packet)

				netstackToPseudoChan <- buf
			}
		}
	}()

	// Start a goroutine which reads from the pseudoToNetstackChan and injects those packets into netstack
	go func() {
		for {
			buf := <-pseudoToNetstackChan
			logger.Debug("From pseudoToNetstackChan", "buf", buf)
			pktBufferPayload := buffer.MakeWithData(buf)
			pktBufferOptions := stack.PacketBufferOptions{
				Payload: pktBufferPayload,
			}
			pktBuffer := stack.NewPacketBuffer(pktBufferOptions)

			logger.Debug("Writing packet to linkEP", "pktBuffer", pktBuffer)
			linkEP.InjectInbound(ipv4.ProtocolNumber, pktBuffer)
		}
	}()

	protectConnection := pseudotcp.SocketProtector(func(fd int) error {
		logger.Debug("Protecting", "fd", fd)
		return nil
	})

	sendPacket = func(packet []byte, length int) error {
		p := gopacket.NewPacket(packet[:], layers.LayerTypeIPv4, gopacket.Default)
		logger.Debug("Sending to netstack", "p", p)

		sendPacketBuf := make([]byte, len(packet))
		copy(sendPacketBuf, packet)
		pseudoToNetstackChan <- sendPacketBuf
		return nil
	}

	pTCPConfig := &pseudotcp.PseudoTCPConfig{
		Logger:     logger,
		SendPacket: sendPacket,

		// Our test sends to a non-publicly route-able IP
		ProhibitDisallowedIPPorts: false,
	}

	pTCP = pseudotcp.NewPseudoTCP(pTCPConfig)

	pTCP.ConfigureProtect(protectConnection)

	err = pTCP.Init(containerIP, "8444")

	if err != nil {
		log.Fatalf("failed to pTCP.Init: %v", err)
	}

	defer pTCP.Shutdown()

	// Start a goroutine which reads from the netstackToPseudoChan and sends those packets to the pseudotcp stack
	go func() {
		for {
			buf := <-netstackToPseudoChan
			pTCP.Send(buf)
		}
	}()

	// Attach an address to the network interface
	tcpErr = netstack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: endpointIP.WithPrefix(),
	}, stack.AddressProperties{})
	if tcpErr != nil {
		log.Fatalf("failed to AddProtocolAddress: %v", tcpErr)
	}

	netstack.SetSpoofing(1, true)
	netstack.SetPromiscuousMode(1, true)
	netstack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")), tcpip.MaskFrom("\x00\x00\x00\x00"))
	r := tcpip.Route{
		Destination: subnet,
		Gateway:     gatewayIP,
		NIC:         nicID,
	}
	if err != nil {
		log.Fatalf("failed to create NewSubnet: %v", err)
	}

	netstack.AddRoute(r)

	logger.Debug("Route table", "GetRouteTable", netstack.GetRouteTable())
	nicAddress, tcpErr := netstack.GetMainNICAddress(nicID, ipv4.ProtocolNumber)
	if tcpErr != nil {
		log.Fatalf("failed to GetMainNICAddress: %v", tcpErr)
	}
	logger.Debug("NICAddress", "GetMainNICAddress", nicAddress)

	m.Run()
}
