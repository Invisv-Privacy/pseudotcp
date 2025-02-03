package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/invisv-privacy/pseudotcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSGet(t *testing.T) {
	chanBufferLength := 1000

	// We need 2 channels, one where we can put packets coming from pseudotcp destined for our netstack and the other in the opposite direction
	var pseudoToNetstackChan = make(chan []byte, chanBufferLength)
	var netstackToPseudoChan = make(chan []byte, chanBufferLength)

	// Start target HTTP/S server
	expectedResponse := "test http response data"
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method, "Request to the end target server should be a GET")
		_, err := fmt.Fprint(w, expectedResponse)
		require.NoError(t, err, "fmt.Fprintf")
	}))

	// We want to listen on 0.0.0.0 because the proxy container will be on a different non-localhost network.
	// In order to do that we have this kind of awkward hack borrowed from:
	// https://stackoverflow.com/a/42218765/1787596
	l, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err, "httptest server net.Listen")

	// Swap out the default test server listener with our custom one listening on 0.0.0.0
	require.NoError(t, ts.Listener.Close(), "ts.Listener.Close()")
	ts.Listener = l
	ts.EnableHTTP2 = true

	ts.StartTLS()
	defer ts.Close()

	logger.Debug("Test server listening", "ts", ts)

	urlSplit := strings.Split(ts.URL, ":")
	port := urlSplit[len(urlSplit)-1]

	dockerHostURL := fmt.Sprintf("https://%v:%v", containerGateway, port)

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
	require.Empty(t, tcpErr, "CreateNIC")

	// Read from the netstack link and send appropriate packets to pseudotcp
	go func() {
		ctxLogger := logger.With("context", "Reading from linkEP and sending to netstackToPseudoChan")
		for {
			pkt := linkEP.ReadContext(context.Background())
			ctxLogger.Debug("Read Packet from linkEP", "pkt", pkt)
			if pkt == nil {
				break
			} else if pkt.PktType == tcpip.PacketOutgoing {
				b := pkt.ToBuffer()
				pkt.DecRef()

				buf := make([]byte, b.Size())
				_, err := b.ReadAt(buf, 0)

				// EOF is the only acceptable "error" here
				if err != nil {
					require.ErrorIs(t, err, io.EOF)
				}

				packet := gopacket.NewPacket(buf[:], layers.LayerTypeIPv4, gopacket.Default)

				ctxLogger.Debug("Sending to netstackToPseudoChan", "packet", packet)

				netstackToPseudoChan <- buf
			}
		}
	}()

	// Start a goroutine which reads from the pseudoToNetstackChan and injects those packets into netstack
	go func() {
		ctxLogger := logger.With("context", "reading from pseudoToNetstackChan and writing to linkEP")
		for {
			buf := <-pseudoToNetstackChan
			ctxLogger.Debug("From pseudoToNetstackChan", "buf", buf)
			pktBufferPayload := buffer.MakeWithData(buf)
			pktBufferOptions := stack.PacketBufferOptions{
				Payload: pktBufferPayload,
			}
			pktBuffer := stack.NewPacketBuffer(pktBufferOptions)

			ctxLogger.Debug("Writing packet to linkEP", "pktBuffer", pktBuffer)
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
	require.Empty(t, tcpErr, "AddProtocolAddress")

	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")), tcpip.MaskFrom("\x00\x00\x00\x00"))
	r := tcpip.Route{
		Destination: subnet,
		Gateway:     gatewayIP,
		NIC:         nicID,
	}
	require.NoError(t, err, "NewSubnet")
	s.AddRoute(r)

	logger.Debug("Route table", "GetRouteTable", s.GetRouteTable())
	nicAddress, tcpErr := s.GetMainNICAddress(nicID, ipv4.ProtocolNumber)
	require.Empty(t, tcpErr, "GetMainNICAddress")
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

	err = pseudotcp.Init(sendPacket, true, containerIP, "8444")
	require.NoError(t, err, "Init")

	defer pseudotcp.Shutdown()

	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())

	tlsDialWrapper := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		tlsConf := &tls.Config{
			RootCAs: certpool,
			// It seems as though the httptest TLS server uses this arbitrarily as its ServerName 🤷
			ServerName: "example.com",
			NextProtos: ts.TLS.NextProtos,
		}

		logger.Debug("dialing", "addr", addr)
		split := strings.Split(addr, ":")
		hostname := split[0]
		port, err := strconv.Atoi(split[1])
		require.NoError(t, err, "strconv.Atoi")

		ips, err := net.LookupIP(hostname)
		require.NoError(t, err, "LookupIP")
		require.NotEmpty(t, ips, "LookupIP not Empty")

		tcpConn, err := gonet.DialTCPWithBind(context.Background(), s, tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFrom4(endpointIP.As4()),
		}, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(ips[0].To4()),
			Port: uint16(port),
		}, ipv4.ProtocolNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to dial TCP: %w", err)
		}
		tlsClient := tls.Client(tcpConn, tlsConf)
		err = tlsClient.Handshake()
		return tlsClient, err
	}

	transport := &http2.Transport{
		DialTLSContext: tlsDialWrapper,
	}

	httpClient := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, dockerHostURL, nil)
	require.NoError(t, err, "NewRequest")

	res, err := httpClient.Do(req)
	require.NoError(t, err, "httpClient.Do")

	logger.Debug("Response from httpClient", "res", res)

	resBody, err := io.ReadAll(res.Body)
	require.NoError(t, err, "io.ReadAll")

	logger.Debug("Read response body", "resBody", resBody)

	assert.Equal(t, []byte(expectedResponse), resBody, "Response body should match server's")
}
