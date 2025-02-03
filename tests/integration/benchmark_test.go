package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/invisv-privacy/pseudotcp"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var sizes = []int{10000, 100000, 1000000, 10000000, 100000000}

func BenchmarkThroughput(b *testing.B) {
	level := slog.LevelInfo
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	chanBufferLength := 1000

	// We need 2 channels, one where we can put packets coming from pseudotcp destined for our netstack and the other in the opposite direction
	var pseudoToNetstackChan = make(chan []byte, chanBufferLength)
	var netstackToPseudoChan = make(chan []byte, chanBufferLength)

	// Start target HTTP/S server that replies with a payload determined by "?size" url query
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sizeString := r.URL.Query().Get("size")
		size, err := strconv.Atoi(sizeString)
		require.NoError(b, err, "strconv.Atoi")
		_, err = io.CopyN(w, rand.Reader, int64(size))
		require.NoError(b, err, "io.CopyN")
	}))

	// We want to listen on 0.0.0.0 because the proxy container will be on a different non-localhost network.
	// In order to do that we have this kind of awkward hack borrowed from:
	// https://stackoverflow.com/a/42218765/1787596
	l, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(b, err, "httptest server net.Listen")

	// Swap out the default test server listener with our custom one listening on 0.0.0.0
	require.NoError(b, ts.Listener.Close(), "ts.Listener.Close()")
	ts.Listener = l

	ts.Start()
	defer ts.Close()

	urlSplit := strings.Split(ts.URL, ":")
	port := urlSplit[len(urlSplit)-1]

	dockerHostURL := fmt.Sprintf("http://%v:%v", containerGateway, port)

	logger.Debug("Test server listening", "ts", ts, "dockerHostURL", dockerHostURL)

	// Create the network Stack
	endpointIP := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	gatewayIP := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})

	var nicID tcpip.NICID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	defer s.Close()

	// Create the network interface
	linkEP := channel.New(128, 1024, "")
	defer linkEP.Close()

	tcpErr := s.CreateNIC(nicID, linkEP)
	require.Empty(b, tcpErr, "CreateNIC")

	// Read from the netstack link and send appropriate packets to pseudotcp
	go func() {
		for {
			pkt := linkEP.ReadContext(context.Background())
			if pkt == nil {
				break
			} else if pkt.PktType == tcpip.PacketOutgoing {
				b := pkt.ToBuffer()
				pkt.DecRef()

				buf := make([]byte, b.Size())
				_, _ = b.ReadAt(buf, 0)

				packet := gopacket.NewPacket(buf[:], layers.LayerTypeIPv4, gopacket.Default)

				logger.Debug("Sending to pseudotcp", "packet", packet)

				netstackToPseudoChan <- buf
			}
		}
	}()

	// Start a goroutine which reads from the pseudoToNetstackChan and injects those packets into netstack
	go func() {
		for {
			buf := <-pseudoToNetstackChan
			// ctxLogger.Debug("From pseudoToNetstackChan", "buf", buf)
			pktBufferPayload := buffer.MakeWithData(buf)
			pktBufferOptions := stack.PacketBufferOptions{
				Payload: pktBufferPayload,
			}
			pktBuffer := stack.NewPacketBuffer(pktBufferOptions)

			linkEP.InjectInbound(ipv4.ProtocolNumber, pktBuffer)
		}
	}()

	// Start a goroutine which reads from the netstackToPseudoChan and sends those packets to the pseudotcp stack
	go func() {
		for {
			buf := <-netstackToPseudoChan
			pseudotcp.Send(buf)
		}
	}()

	// Attach an address to the network interface
	tcpErr = s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: endpointIP.WithPrefix(),
	}, stack.AddressProperties{})
	require.Empty(b, tcpErr, "AddProtocolAddress")

	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")), tcpip.MaskFrom("\x00\x00\x00\x00"))
	r := tcpip.Route{
		Destination: subnet,
		Gateway:     gatewayIP,
		NIC:         nicID,
	}
	require.NoError(b, err, "NewSubnet")
	s.AddRoute(r)

	logger.Debug("Route table", "GetRouteTable", s.GetRouteTable())
	nicAddress, tcpErr := s.GetMainNICAddress(nicID, ipv4.ProtocolNumber)
	require.Empty(b, tcpErr, "GetMainNICAddress")
	logger.Debug("NICAddress", "GetMainNICAddress", nicAddress)

	protectConnection := pseudotcp.SocketProtector(func(fd int) error {
		logger.Debug("Protecting", "fd", fd)
		return nil
	})

	pseudotcp.ConfigureProtect(protectConnection)

	sendPacket := func(packet []byte, length int) error {
		ctxLogger := logger.With("context", "in sendPacket sending to pseudoToNetstackChan")
		p := gopacket.NewPacket(packet[:], layers.LayerTypeIPv4, gopacket.Default)
		ctxLogger.Debug("Sending to netstack", "p", p)

		sendPacketBuf := make([]byte, len(packet))
		copy(sendPacketBuf, packet)
		pseudoToNetstackChan <- sendPacketBuf
		return nil
	}

	// Our test sends to a non-publicly route-able IP
	pseudotcp.ProhibitDisallowedIPPorts = false

	err = pseudotcp.Init(sendPacket, false, containerIP, "8444")
	require.NoError(b, err, "Init")

	defer pseudotcp.Shutdown()

	dialWrapper := func(ctx context.Context, network, addr string) (net.Conn, error) {
		logger.Debug("dialing", "addr", addr)
		split := strings.Split(addr, ":")
		hostname := split[0]
		port, err := strconv.Atoi(split[1])
		require.NoError(b, err, "strconv.Atoi")

		ips, err := net.LookupIP(hostname)
		require.NoError(b, err, "LookupIP")
		require.NotEmpty(b, ips, "LookupIP not Empty")

		return gonet.DialTCPWithBind(context.Background(), s, tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFrom4(endpointIP.As4()),
		}, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(ips[0].To4()),
			Port: uint16(port),
		}, ipv4.ProtocolNumber)
	}

	transport := &http.Transport{
		DialContext: dialWrapper,
	}

	httpClient := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	defaultClient := http.Client{
		Timeout: 30 * time.Second,
	}

	// Test different payload sizes
	for _, size := range sizes {
		b.Run(fmt.Sprintf("with-pseudotcp-payload-%dB", size), func(b *testing.B) {
			url := fmt.Sprintf("%s?size=%d", dockerHostURL, size)
			for i := 0; i < b.N; i++ {
				req, err := http.NewRequest(http.MethodGet, url, nil)
				require.NoError(b, err, "NewRequest")

				res, err := httpClient.Do(req)
				require.NoError(b, err, "httpClient.Do")

				defer func() {
					err := res.Body.Close()
					require.NoError(b, err, "res.Body.Close()")
				}()

				_, err = io.ReadAll(res.Body)
				require.NoError(b, err, "io.ReadAll")
			}
		})

		b.Run(fmt.Sprintf("without-pseudotcp-payload-%dB", size), func(b *testing.B) {
			url := fmt.Sprintf("%s?size=%d", dockerHostURL, size)
			for i := 0; i < b.N; i++ {
				req, err := http.NewRequest(http.MethodGet, url, nil)
				require.NoError(b, err, "NewRequest")

				res, err := defaultClient.Do(req)
				require.NoError(b, err, "httpClient.Do")

				defer func() {
					err := res.Body.Close()
					require.NoError(b, err, "res.Body.Close()")
				}()

				_, err = io.ReadAll(res.Body)
				require.NoError(b, err, "io.ReadAll")
			}
		})
	}
}
