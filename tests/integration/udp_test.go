package integration

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/invisv-privacy/pseudotcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDP(t *testing.T) {
	err := pseudotcp.Init(sendPacket, true, containerIP, "8444")
	require.NoError(t, err, "pseudotcp.Init")

	defer pseudotcp.Shutdown()

	expectedRequest := "hello from client"
	expectedReply := "hello from server"

	// We want to listen on 0.0.0.0 because the proxy container will be on a different non-localhost network.
	// In order to do that we have this kind of awkward hack borrowed from:
	// https://stackoverflow.com/a/42218765/1787596
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	require.NoError(t, err, "ResolveUDPAddr")

	// Create UDP connection
	udpListenConn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err, "ListenUDP")
	defer func() {
		err := udpListenConn.Close()
		require.NoError(t, err, "conn.Close")
	}()

	localAddr := udpListenConn.LocalAddr().(*net.UDPAddr)
	logger.Debug("UDP Server listening", "localAddr", localAddr)

	go func() {
		buffer := make([]byte, 1024)
		for {
			// Read incoming data
			n, remoteAddr, err := udpListenConn.ReadFromUDP(buffer)
			if err != nil {
				break
			}
			require.NoError(t, err, "ReadFromUDP")

			message := string(buffer[:n])
			logger.Debug("Received message", "remoteAddr", remoteAddr, "message", message)

			assert.Equal(t, expectedRequest, message)

			// Send response back to client
			response := []byte(expectedReply)
			_, err = udpListenConn.WriteToUDP(response, remoteAddr)
			require.NoError(t, err, "WriteToUDP")
		}
	}()

	containerGatewayIP := net.ParseIP(containerGateway)
	var udpServerIPBytes [4]byte
	copy(udpServerIPBytes[:], containerGatewayIP.To4())

	logger.Debug("dialing UDP", "containerGatewayIP", containerGatewayIP, "udpServerIPBytes", udpServerIPBytes, "port", localAddr.Port)

	udpClientConn, err := gonet.DialUDP(netstack, &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4(endpointIP.As4()),
	}, &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(udpServerIPBytes),
		Port: uint16(localAddr.Port),
	}, ipv4.ProtocolNumber)

	require.NoError(t, err, "gonet.DialUDP")
	defer func() {
		err := udpClientConn.Close()
		require.NoError(t, err, "conn.Close")
	}()

	_, err = udpClientConn.Write([]byte(expectedRequest))
	require.NoError(t, err, "udpClientConn.Write")

	readBuffer := make([]byte, 1024)
	n, err := udpClientConn.Read(readBuffer)
	require.NoError(t, err, "udpClientConn.Read")

	assert.Equal(t, []byte(expectedReply), readBuffer[:n])
}
