package integration

import (
	"crypto/rand"
	"errors"
	"io"
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

	sendBufferSize := pseudotcp.TUN_MTU - 150
	receiveBufferSize := pseudotcp.INTERNET_MTU - 150
	expectedRequest := make([]byte, sendBufferSize)
	_, err = rand.Read(expectedRequest)
	require.NoError(t, err, "rand.Read")
	expectedReply := make([]byte, receiveBufferSize)
	_, err = rand.Read(expectedReply)
	require.NoError(t, err, "rand.Read")

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

		var remoteAddr *net.UDPAddr
		buffer := make([]byte, sendBufferSize)
		readLength := 0
		for {
			n := 0
			// Read incoming data
			n, remoteAddr, err = udpListenConn.ReadFromUDP(buffer[readLength:])

			logger.Debug("ReadFromUDP", "remoteAddr", remoteAddr, "n", n, "err", err)

			readLength += n
			if readLength >= sendBufferSize || errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err, "ReadFromUDP")
		}

		logger.Debug("Received message", "remoteAddr", remoteAddr, "readLength", readLength)
		assert.Equal(t, expectedRequest, buffer[:readLength])

		// Send response back to client
		n, err := udpListenConn.WriteToUDP(expectedReply, remoteAddr)
		logger.Debug("udpListenConn.WriteToUDP", "n", n, "err", err)
		require.NoError(t, err, "WriteToUDP")
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

	n, err := udpClientConn.Write(expectedRequest)
	logger.Debug("udpClientConn.Write", "n", n, "err", err)
	require.NoError(t, err, "udpClientConn.Write")

	readBuffer := make([]byte, receiveBufferSize)

	n, err = udpClientConn.Read(readBuffer)

	logger.Debug("udpClientConn.Read", "n", n, "err", err)

	require.NoError(t, err, "udpClientConn.Read")

	logger.Debug("received message from udpClientConn.Read", "n", n, "err", err)

	assert.Equal(t, expectedReply, readBuffer[:n])
}
