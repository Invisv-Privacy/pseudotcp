package pseudotcp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	masqueH2 "github.com/invisv-privacy/masque/http2"
)

const (
	// MTU of the TUN interface we're using, has to match Android.
	TUN_MTU                   = 32000
	INTERNET_MTU              = 1500
	DNS_CACHE_TIMEOUT_SECONDS = 300
	DEFAULT_PROXY_PORT        = "443"
)

var logger *slog.Logger

type SendPacket func(packet []byte, length int) error

var toLinux SendPacket

func Init(sendPacket SendPacket, verbose bool, proxyFQDN, proxyPort string) error {

	if logger == nil {
		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		}
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		}))
		slog.SetDefault(logger)
	}

	logger.Debug("Initializing", "proxyFQDN", proxyFQDN)

	toLinux = sendPacket
	return UserStackInit(proxyFQDN, proxyPort)
}

func Send(packetData []byte) {
	UserStackIPProcessPacket(packetData)
}

// TCPFlow tracks the state of a virtual TCP connection between Android and the MASQUE proxy.
type TCPFlow struct {
	src            uint32
	sport          uint16
	dst            uint32
	dport          uint16
	seq            uint32
	ack            uint32
	rwin           int32
	rwinScale      uint8
	garbageCollect bool
	proxyConn      io.ReadWriteCloser
}

// ProhibitDisallowedIPPorts determines whether we check if packets are heading to an "allowed IP/Port" tuple
// And if we should prohibit them w/ a host unreachable code
var ProhibitDisallowedIPPorts = true

// activeTCPFlows stores a mapping from client port to the flow structure for TCP flows.
var activeTCPFlows [65536]*TCPFlow

// pendingTCPSYNs stores a mapping from client port to the flow structure for TCP flows while we're waiting for the MASQUE server to reply.
var pendingTCPSYNs = make(map[uint16]*TCPFlow)
var pendingTCPSYNsMutex sync.Mutex

// establishedTCPFlows channel of TCP flows whose connection establishment has completed.
var establishedTCPFlows = make(chan *TCPFlow)
var establishedTCPFlowsCount int32

// wakeupUDPConn is used by established TCP flow goroutines to wake up the datapath to process them.
var wakeupUDPConn net.Conn

const (
	WAKEUP_PACKET_IP_PORT  string = "10.10.10.10:1234" // Invalid destination for the wakeup packet.
	WAKEUP_PACKET_IP_VALUE byte   = 10
)

// UDPFlow tracks the state of a MASQUE connection to a _destination IP/port_ (different from TCP).
type UDPFlow struct {
	src            uint32
	sport          uint16
	dst            uint32
	dport          uint16
	garbageCollect bool
	proxyConn      io.ReadWriteCloser
}

// UDPFlowKey keys the activeUDPFlows map with the client (src) IP/port and server (dst) IP/port.
type UDPFlowKey struct {
	src   uint32
	sport uint16
	dst   uint32
	dport uint16
}

// relayActive indicates whether we can process packets.
var relayActive bool

// activeUDPFlows stores a mapping from client (src) IP/port and server (dst) IP/port to the flow structure for UDP flows.
var activeUDPFlows map[UDPFlowKey]*UDPFlow

// deadUDPFlows stores a list of UDP flows that have been closed.
var deadUDPFlows []*UDPFlow

// proxyClient stores the HTTP/2 or HTTP/3 connection to the MASQUE proxy.
var proxyClient *masqueH2.Client

// currentProxyFQDN stores the DNS name of the current proxy.
var currentProxyFQDN string

// proxyIP stores the IP of the current proxy.
var proxyIP string

// proxyPort stores the port that the current proxy is listening on.
var proxyPort string

// Pre-baked packets that have common fields set and the rest of the headers set to defaults or zero.
var (
	preBakedSynAck  [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE + 4]byte // extra 4 bytes for WSopt
	preBakedAck     [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte
	preBakedRst     [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte
	preBakedSegment [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte

	preBakedUDP [DEFAULT_IP_HDR_SIZE + DEFAULT_UDP_HDR_SIZE]byte

	preBakedICMP [DEFAULT_IP_HDR_SIZE + DEFAULT_ICMP_UNREACHABLE_HDR_SIZE]byte
)

func clearActiveTCPFlows() {
	for i := range activeTCPFlows {
		if activeTCPFlows[i] != nil {
			activeTCPFlows[i].garbageCollect = true
			if err := activeTCPFlows[i].proxyConn.Close(); err != nil {
				logger.Error("Error calling activeTCPFlows[i].proxyConn.Close()", "err", err, "activeTCPFlows[i]", activeTCPFlows[i])
			}
		}
		activeTCPFlows[i] = nil
	}
}

func initActiveFlows() {
	if activeUDPFlows != nil {
		terminateActiveFlows()
	}
	clearActiveTCPFlows()
	activeUDPFlows = make(map[UDPFlowKey]*UDPFlow)
	deadUDPFlows = make([]*UDPFlow, 0)
	if proxyClient != nil {
		// TODO: any Close/cleanup for proxyClient?
		proxyClient = nil
	}
}

func terminateActiveFlows() {
	for _, flow := range activeUDPFlows {
		flow.garbageCollect = true
		err := flow.proxyConn.Close()
		if err != nil {
			logger.Error("Error calling flow.proxyConn.Close()", "err", err, "flow.proxyConn", flow.proxyConn)
		}
	}
	clearActiveTCPFlows()
	activeUDPFlows = nil
	deadUDPFlows = nil
}

// Computes and sets the checksum for the given IP header.
// Checksum code borrowed from google/gopacket:
// [https://github.com/google/gopacket/blob/master/layers/tcpip.go]
func computeIPChecksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}

// Checksums the given TCP/UDP header.
// Checksum code borrowed from google/gopacket:
// [https://github.com/google/gopacket/blob/master/layers/tcpip.go]
func checksumL4(headerAndPayload []byte, protocol uint32, srcIP net.IP, dstIP net.IP) uint16 {
	if protocol == uint32(PROTO_TCP) {
		headerAndPayload[TCP_CHECK] = 0
		headerAndPayload[TCP_CHECK+1] = 0
	} else if protocol == uint32(PROTO_UDP) {
		headerAndPayload[UDP_CHECK] = 0
		headerAndPayload[UDP_CHECK+1] = 0
	} else if protocol == uint32(PROTO_ICMP) {
		headerAndPayload[ICMP_CHECK] = 0
		headerAndPayload[ICMP_CHECK+1] = 0
	}

	var csum uint32

	if protocol != uint32(PROTO_ICMP) {
		csum += (uint32(srcIP[0]) + uint32(srcIP[2])) << 8
		csum += uint32(srcIP[1]) + uint32(srcIP[3])
		csum += (uint32(dstIP[0]) + uint32(dstIP[2])) << 8
		csum += uint32(dstIP[1]) + uint32(dstIP[3])

		totalLen := uint32(len(headerAndPayload))

		csum += protocol
		csum += totalLen & 0xffff
		csum += totalLen >> 16
	}

	return tcpipChecksum(headerAndPayload, csum)
}

// Calculate the TCP/IP checksum defined in rfc1071. The passed-in csum is any
// initial checksum data that's already been computed.
// Checksum code borrowed from google/gopacket:
// [https://github.com/google/gopacket/blob/master/layers/tcpip.go]
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

// setIPandL4Checksum sets the IP and TCP checksums for the given IP packet.
func setIPandL4Checksum(buf []byte, proto uint8) {
	// Compute IP checksum.
	cksum := computeIPChecksum(buf[:DEFAULT_IP_HDR_SIZE])
	buf[IP_CHECK] = byte(cksum >> 8)
	buf[IP_CHECK+1] = byte(cksum)

	// Compute TCP checksum.
	srcIP := buf[IP_SRC : IP_SRC+4]
	dstIP := buf[IP_DST : IP_DST+4]
	l4Pkt := buf[DEFAULT_IP_HDR_SIZE:]
	l4sum := checksumL4(l4Pkt, uint32(proto), srcIP, dstIP)

	if proto == PROTO_TCP {
		l4Pkt[TCP_CHECK] = byte(l4sum >> 8)
		l4Pkt[TCP_CHECK+1] = byte(l4sum)
	} else if proto == PROTO_UDP {
		l4Pkt[UDP_CHECK] = byte(l4sum >> 8)
		l4Pkt[UDP_CHECK+1] = byte(l4sum)
	} else if proto == PROTO_ICMP {
		l4Pkt[ICMP_CHECK] = byte(l4sum >> 8)
		l4Pkt[ICMP_CHECK+1] = byte(l4sum)
	}
}

// setTCPHdr fills in the TCP header |buf| with the given field values.
func setTCPHdr(buf []byte, sport, dport uint16, seq uint32, ack uint32) {
	buf[TCP_SRC_PORT] = byte(sport >> 8)
	buf[TCP_SRC_PORT+1] = byte(sport & 0xff)
	buf[TCP_DST_PORT] = byte(dport >> 8)
	buf[TCP_DST_PORT+1] = byte(dport & 0xff)
	buf[TCP_SEQ_NUM] = byte(seq >> 24)
	buf[TCP_SEQ_NUM+1] = byte(seq >> 16)
	buf[TCP_SEQ_NUM+2] = byte(seq >> 8)
	buf[TCP_SEQ_NUM+3] = byte(seq)
	buf[TCP_ACK_NUM] = byte(ack >> 24)
	buf[TCP_ACK_NUM+1] = byte(ack >> 16)
	buf[TCP_ACK_NUM+2] = byte(ack >> 8)
	buf[TCP_ACK_NUM+3] = byte(ack)
}

// makeIPHdr fills in the given header |buf| with default values.
func makeIPHdr(buf []byte, proto byte) {
	buf[IP_VERSION_IHL] = 0x45
	buf[IP_TTL] = 0x40
	buf[IP_PROTO] = proto
	buf[IP_CHECK] = 0x00
	buf[IP_CHECK+1] = 0x00
}

// setIPHdr fills in the IP header |buf| with the given field values.
func setIPHdr(buf []byte, src, dst uint32, len uint16) {
	buf[IP_LEN] = byte(len >> 8)
	buf[IP_LEN+1] = byte(len)
	buf[IP_SRC] = byte(src >> 24)
	buf[IP_SRC+1] = byte(src >> 16)
	buf[IP_SRC+2] = byte(src >> 8)
	buf[IP_SRC+3] = byte(src)
	buf[IP_DST] = byte(dst >> 24)
	buf[IP_DST+1] = byte(dst >> 16)
	buf[IP_DST+2] = byte(dst >> 8)
	buf[IP_DST+3] = byte(dst)
}

// setUDPHdr fills in the UDP header |buf| with the given field values.
func setUDPHdr(buf []byte, sport, dport uint16, len uint16) {
	buf[UDP_SRC_PORT] = byte(sport >> 8)
	buf[UDP_SRC_PORT+1] = byte(sport & 0xff)
	buf[UDP_DST_PORT] = byte(dport >> 8)
	buf[UDP_DST_PORT+1] = byte(dport & 0xff)
	buf[UDP_LEN] = byte(len >> 8)
	buf[UDP_LEN+1] = byte(len)
}

// setICMPHdr fills in the ICMP header |buf| with the given field values.
func setICMPHdr(buf []byte, t, code uint8, mtu uint16) {
	buf[ICMP_TYPE] = t
	buf[ICMP_CODE] = code
	buf[ICMP_NEXT_HOP_MTU] = byte(mtu >> 8)
	buf[ICMP_NEXT_HOP_MTU+1] = byte(mtu & 0xff)
}

// preBakeSynAck fills in the pre-baked SYN-ACK packet.
func preBakeSynAck() {
	buf := preBakedSynAck[:]
	makeIPHdr(buf, PROTO_TCP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]

	buf[TCP_DATA_OFF] = 0x60
	buf[TCP_FLAGS] = FLAG_BIT_SYN | FLAG_BIT_ACK
	buf[TCP_WINDOW] = 0xFF
	buf[TCP_WINDOW+1] = 0xFF

	// set window scale option
	buf[TCP_OPTIONS] = 0x03
	buf[TCP_OPTIONS+1] = 0x03
	buf[TCP_OPTIONS+2] = 0x09
	buf[TCP_OPTIONS+3] = 0x00
}

// preBakeAck fills in the pre-baked ACK packet.
func preBakeAck() {
	buf := preBakedAck[:]
	makeIPHdr(buf, PROTO_TCP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]

	buf[TCP_DATA_OFF] = 0x50
	buf[TCP_FLAGS] = FLAG_BIT_ACK
	buf[TCP_WINDOW] = 0xFF
	buf[TCP_WINDOW+1] = 0xFF
}

// preBakeRst fills in the pre-baked RST packet.
func preBakeRst() {
	buf := preBakedRst[:]
	makeIPHdr(buf, PROTO_TCP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]

	buf[TCP_DATA_OFF] = 0x50
	buf[TCP_FLAGS] = FLAG_BIT_RST
	buf[TCP_WINDOW] = 0xFF
	buf[TCP_WINDOW+1] = 0xFF
}

// preBakeSegment fills in the pre-baked segment packet.
func preBakeSegment() {
	buf := preBakedSegment[:]
	makeIPHdr(buf, PROTO_TCP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]

	buf[TCP_DATA_OFF] = 0x50
	buf[TCP_FLAGS] = FLAG_BIT_ACK
	buf[TCP_WINDOW] = 0xFF
	buf[TCP_WINDOW+1] = 0xFF
}

// preBakeUDP fills in the pre-baked UDP packet.
func preBakeUDP() {
	buf := preBakedUDP[:]
	makeIPHdr(buf, PROTO_UDP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]
	buf[UDP_SRC_PORT] = 0x00
	buf[UDP_SRC_PORT+1] = 0x00
	buf[UDP_DST_PORT] = 0x00
	buf[UDP_DST_PORT+1] = 0x00
	buf[UDP_LEN] = 0x00
	buf[UDP_LEN+1] = 0x08
	buf[UDP_CHECK] = 0x00
	buf[UDP_CHECK+1] = 0x00
}

// prebakeICMP fills in the pre-baked ICMP unreachable packet.
func preBakeICMP() {
	buf := preBakedICMP[:]
	makeIPHdr(buf, PROTO_ICMP)
	buf = buf[DEFAULT_IP_HDR_SIZE:]
	buf[ICMP_TYPE] = 0x03
	buf[ICMP_CODE] = 0x03
	buf[ICMP_CHECK] = 0x00
	buf[ICMP_CHECK+1] = 0x00
}

// preBakePackets generates the standard pre-baked packets.
func preBakePackets() {
	preBakeSynAck()
	preBakeAck()
	preBakeRst()
	preBakeSegment()
	preBakeUDP()
	preBakeICMP()
}

// replyInitialSyn creates a SYN-ACK reply to an initial SYN, stores a flow entry, and returns the generated SYN-ACK.
func replyInitialSyn(src, dst uint32, sport, dport uint16, seq, ack uint32) [SYNACK_SIZE]byte {
	// Send SYN-ACK
	buf := [SYNACK_SIZE]byte{}
	copy(buf[:], preBakedSynAck[:])

	setIPHdr(buf[:], dst, src, uint16(SYNACK_SIZE))
	setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], dport, sport, seq, ack)
	setIPandL4Checksum(buf[:], PROTO_TCP)

	return buf
}

// replyRst generates a RST reply to any termination or error condition, and returns the generated RST.
func replyRst(src, dst uint32, sport, dport uint16, seq, ack uint32) [RST_SIZE]byte {
	// Send RST
	buf := [RST_SIZE]byte{}
	copy(buf[:], preBakedRst[:])

	setIPHdr(buf[:], dst, src, uint16(RST_SIZE))
	setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], dport, sport, seq, ack)
	setIPandL4Checksum(buf[:], PROTO_TCP)

	return buf
}

// replyAck generates a ACK reply to a normal data segment, and returns the generated ACK.
func replyAck(src, dst uint32, sport, dport uint16, seq, ack uint32) [ACK_SIZE]byte {
	// Send ACK
	buf := [ACK_SIZE]byte{}
	copy(buf[:], preBakedAck[:])

	setIPHdr(buf[:], dst, src, uint16(ACK_SIZE))
	setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], dport, sport, seq, ack)
	setIPandL4Checksum(buf[:], PROTO_TCP)

	return buf
}

// setupMasque initiates a MASQUE connection via an already-connected proxy to flow.dst:flow.dport.
// It also starts a goroutine to handle the MASQUE connection, by reading data from it and injecting that data as TCP segments.
func setupMasque(dstIP net.IP, flow *TCPFlow) {
	host := fmt.Sprintf("%v:%v", dstIP, flow.dport)

	logger.Info("Connecting TCP", "host", host)
	if c, err := proxyClient.CreateTCPStream(host); err != nil {
		// TODO: add more robust error handling, since it's possible we're offline.
		// TODO: possibly attempt to reconnect to the proxy, and if that fails, make sure to signal that the VPN is down.
		logger.Error("Error setting up masque for flow", "err", err, "host", host)
		pendingTCPSYNsMutex.Lock()
		delete(pendingTCPSYNs, flow.sport)
		pendingTCPSYNsMutex.Unlock()
		return
	} else {
		logger.Info("Connected", "host", host)
		flow.proxyConn = c
	}

	go func() {
		establishedTCPFlows <- flow // blocks because establishedTCPFlows is an unbuffered channel

		// This Lock()/Unlock() prevents us from starting the goroutine until the SYNACK is sent, because the outbound thread will have the lock.
		// The unbuffered channel functions as one lock (really a semaphore), because this function can't proceed until the select in the outbound thread.
		// When that select takes place, the outbound thread holds the other lock (pendingTCPSYNsMutex),
		// so this (and any other worker goroutine) can't actually start until the outbound thread has finished its work of marking all pending flows as active.
		//
		// TODO: consider changing establishedTCPFlows to take {flow,signalingChannel} to signal that the outbound thread has finished its work, and then this goroutine can start.
		pendingTCPSYNsMutex.Lock()
		//nolint:staticcheck
		pendingTCPSYNsMutex.Unlock()
		logger.Debug("setupMasque goroutine started for flow", "flow", flow)

		var b [TUN_MTU]byte
		var buf []byte = b[:]
		var b2 [TUN_MTU]byte
		var buf2 []byte = b2[:]

		copy(buf[:], preBakedSegment[:])
		copy(buf2[:], preBakedSegment[:])

		const totalHdrLen = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE
		const SAFE_PACKET_SIZE = 1500
		dummyPacketToggle := true // when rwin limited, used to send a zero-payload dummy packet every other packet

		for !flow.garbageCollect {
			targetReadLen := len(buf)

			rwin := atomic.LoadInt32(&flow.rwin)
			if dummyPacketToggle && rwin < TUN_MTU {
				//nolint:ineffassign // TODO: why are we doing this? //
				targetReadLen = totalHdrLen // create a dummy segment

				ack := atomic.LoadUint32(&flow.ack)
				setIPHdr(buf[:], flow.dst, flow.src, uint16(totalHdrLen))
				setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], flow.dport, flow.sport, flow.seq, ack)
				setIPandL4Checksum(buf[:totalHdrLen], PROTO_TCP)

				err := pseudoSendToLinux(buf[:totalHdrLen])
				if err != nil {
					logger.Error("Error sending dummy segment to Linux", "err", err)
				}

				logger.Debug("flow rwin limited too much, sleeping")
				time.Sleep(100 * time.Millisecond)

				dummyPacketToggle = false
				continue
			}
			dummyPacketToggle = true

			// If the receiver has very little receive window left, choose a safe packet size.
			if rwin < (3 * TUN_MTU) {
				runtime.Gosched() // yield to allow the inbound thread to process an ACK
				targetReadLen = SAFE_PACKET_SIZE
				logger.Debug("adjusting targetReadLen, based on rwin", "targetReadLen", targetReadLen, "rwin", rwin)
			}

			n, err := flow.proxyConn.Read(buf[totalHdrLen:targetReadLen])

			// Process data before considering the possibility of an error.
			if n > 0 {
				var pktsize int = n + totalHdrLen

				// flow.ack can be modified by the other direction.
				ack := atomic.LoadUint32(&flow.ack)

				setIPHdr(buf[:], flow.dst, flow.src, uint16(pktsize))
				setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], flow.dport, flow.sport, flow.seq, ack)
				setIPandL4Checksum(buf[:pktsize], PROTO_TCP)

				atomic.AddUint32(&flow.seq, uint32(n))
				err = pseudoSendToLinux(buf[:pktsize])

				if err == nil && pktsize > (TUN_MTU>>1) {
					logger.Debug("Successful send above half MTU", "pktsize", pktsize)
				}
				if err != nil && strings.Contains(err.Error(), "ENOBUFS") {
					logger.Warn("Got ENOBUFS, splitting packet")

					// If the packet was too large for the TUN, chop it in half and try again.
					n2 := n >> 1 // amount of payload to put in second TCP segment
					pktsize2 := n2 + totalHdrLen

					n1 := n - n2 // amount of payload to put in first TCP segment
					pktsize1 := n1 + totalHdrLen

					copy(buf2[totalHdrLen:], buf[totalHdrLen+n1:])
					setIPHdr(buf2[:], flow.dst, flow.src, uint16(pktsize2))
					setTCPHdr(buf2[DEFAULT_IP_HDR_SIZE:], flow.dport, flow.sport, flow.seq+uint32(n1), ack)
					setIPandL4Checksum(buf2[:pktsize2], PROTO_TCP)

					// adjust the first packet
					setIPHdr(buf[:], flow.dst, flow.src, uint16(pktsize1))
					setTCPHdr(buf[DEFAULT_IP_HDR_SIZE:], flow.dport, flow.sport, flow.seq, ack)
					setIPandL4Checksum(buf[:pktsize1], PROTO_TCP)

					logger.Debug("Sending split packet")
					err = pseudoSendToLinux(buf[:pktsize1])
					if err == nil {
						err = pseudoSendToLinux(buf2[:pktsize2])
						if err == nil {
							// shrink buf and buf2 to half their current size
							buf = buf[:len(buf)>>1]
							buf2 = buf2[:len(buf2)>>1]
							logger.Debug("Shrank buf and buf2", "len(buf)", len(buf), "len(buf2)", len(buf2))
						}
					}
					if err != nil {
						logger.Error("Failed to send split packet", "err", err)
					}
				} else if err != nil {
					logger.Error("Failure sending packet", "err", err)
				}

				atomic.AddInt32(&flow.rwin, int32(-n))
			}

			if err != nil {
				logger.Error("Error reading from port", "flow.sport", flow.sport, "err", err, "flow", flow)
				flow.garbageCollect = true
				err := flow.proxyConn.Close()
				if err != nil {
					logger.Error("Error in flow.proxyConn.Close()", "err", err, "flow.proxyConn", flow.proxyConn)
				}
			}
		}

		// TODO: Close / cleanup the masque connection.
	}()

	atomic.AddInt32(&establishedTCPFlowsCount, 1)
	logger.Debug("setupMasque about to send wakeup")
	_, err := wakeupUDPConn.Write([]byte{0x00})
	if err != nil {
		logger.Error("Error writing to wakeup UDP socket", "err", err)
	}
}

// setupUDPMasque initiates a UDP MASQUE connection via an already-connected proxy to flow.dst:flow.dport.
// It also starts a goroutine to handle the UDP MASQUE connection, sending datagrams to Linux.
func setupUDPMasque(dstIP net.IP, flow *UDPFlow) error {
	host := fmt.Sprintf("%v:%v", dstIP, flow.dport)

	logger.Debug("Connecting UDP", "host", host)
	if c, err := proxyClient.CreateUDPStream(host); err != nil {
		return err
	} else {
		flow.proxyConn = c
	}

	go func() {
		var buf [INTERNET_MTU]byte
		copy(buf[:], preBakedUDP[:])
		const totalHdrLen = DEFAULT_IP_HDR_SIZE + DEFAULT_UDP_HDR_SIZE

		for !flow.garbageCollect {
			n, err := flow.proxyConn.Read(buf[totalHdrLen:])

			// Process data before considering the possibility of an error.
			if n > 0 {
				var pktsize int = n + totalHdrLen

				setIPHdr(buf[:], flow.dst, flow.src, uint16(pktsize))
				setUDPHdr(buf[DEFAULT_IP_HDR_SIZE:], flow.dport, flow.sport, uint16(n+DEFAULT_UDP_HDR_SIZE))
				setIPandL4Checksum(buf[:pktsize], PROTO_UDP)

				err := pseudoSendToLinux(buf[:pktsize])
				if err != nil {
					logger.Error("Error in pseudoSendToLinux", "err", err, "flow", flow)
				}
			}

			if err != nil {
				logger.Error("Error reading from port", "flow.sport", flow.sport, "err", err, "flow", flow)
				flow.garbageCollect = true
				// append this flow to deadUDPFlows
				deadUDPFlows = append(deadUDPFlows, flow)
			}
		}

		// TODO: Close / cleanup the masque connection.
	}()
	return nil
}

// CurrentProxyIP returns the IP of the Proxy A server we are connected to.
// If relay is not active, returns empty string.
func CurrentProxyIP() string {
	if relayActive {
		return proxyIP
	}
	return ""
}

// connectToProxy connects to the MASQUE proxy and initializes the default MASQUE client.
func connectToProxy() error {
	if currentProtect == nil {
		return errors.New("currentProtect is nil")
	}

	proxy := currentProxyFQDN

	ip := net.ParseIP(proxy)
	if ip != nil && ip.To4() != nil {
		// We have an ipv4 address, we can just use that
		proxyIP = ip.String()
	} else if ip != nil && ip.To4() == nil {
		// We've been given an ipv6 address, we can return an error
		return fmt.Errorf("ipv6 proxy addresses are unsupported, proxyIP: %v", ip)
	} else if ip == nil {
		// Not an ip address, we need to look it up
		resolvedProxyIP, err := ResolveDOHJSON(proxy)
		if err != nil {
			return fmt.Errorf("failed to lookup proxy hostname: %w", err)
		} else {
			proxyIP = resolvedProxyIP
		}
	}
	var proxyAddr string
	if proxyPort != "" {
		proxyAddr = proxyIP + ":" + proxyPort
	} else {
		proxyAddr = proxyIP + ":" + DEFAULT_PROXY_PORT
	}

	logger.Debug("resolved proxy", "proxyAddr", proxyAddr)

	config := masqueH2.ClientConfig{
		ProxyAddr:  proxyAddr,
		IgnoreCert: true,
		Logger:     logger,
		AuthToken:  "fake-token",
		Prot:       masqueH2.SocketProtector(currentProtect),
	}

	proxyClient = masqueH2.NewClient(config)

	err := proxyClient.ConnectToProxy()
	if err != nil {
		return fmt.Errorf("failed to ConnectToProxy: %w", err)
	}

	initDnsClient()

	return nil
}

func initWakeupUDPConn() error {
	// TODO: clean up wakeupUDPConn from before.

	var err error
	wakeupUDPConn, err = net.Dial("udp4", WAKEUP_PACKET_IP_PORT)
	if err != nil {
		return err
	}
	return nil
}

// UserStackInit initializes the userspace network stack module. This must be called before any other UserStack function.
// proxyFQDN is the DNS name of the MASQUE proxy server.
// proxyPort is the port number that the MASQUE proxy server is listening on.
func UserStackInit(proxyFQDN, port string) error {
	logger.Info("Starting Relay")

	proxyIP = ""
	if toLinux == nil {
		return errors.New("toLinux is nil")
	}
	currentProxyFQDN = proxyFQDN
	proxyPort = port

	initActiveFlows()
	preBakePackets()
	if err := initWakeupUDPConn(); err != nil {
		logger.Error("Error in initWakeupUDPConn", "err", err)
	}

	err := connectToProxy()
	if err != nil {
		relayActive = false
		logger.Error("failed connecting to proxy", "err", err)
		return err
	}
	relayActive = true
	return nil
}

// ReconnectToProxy indicates to the Relay code that it should try to connect to the proxy again.
// This is good to call when Android detects that a network interface has come back up.
func ReconnectToProxy(proxyFQDN, port string) error {
	proxyIP = ""
	proxyPort = port

	currentProxyFQDN = proxyFQDN

	relayActive = false
	initActiveFlows()
	err := connectToProxy()
	if err != nil {
		relayActive = false
		return err
	}
	relayActive = true
	return nil
}

func Shutdown() {
	relayActive = false
	terminateActiveFlows()
	if proxyClient != nil {
		// TODO: any Close/cleanup for proxyClient?
		proxyClient = nil
	}
	proxyIP = ""
}

func processPendingTCPSYNs() {
	waitingFlows := atomic.LoadInt32(&establishedTCPFlowsCount)
	if waitingFlows > 0 {
		pendingTCPSYNsMutex.Lock()
		defer pendingTCPSYNsMutex.Unlock()
		for {
			select {
			case flow := <-establishedTCPFlows:
				delete(pendingTCPSYNs, flow.sport)
				buf := replyInitialSyn(flow.src, flow.dst, flow.sport, flow.dport, flow.seq, flow.ack)
				flow.seq += 1
				activeTCPFlows[flow.sport] = flow

				if err := pseudoSendToLinux(buf[:]); err != nil {
					logger.Error("Error in pseudoSendToLinux", "err", err)
				}

				atomic.AddInt32(&establishedTCPFlowsCount, -1)
			default:
				return
			}
		}
	}
}

// processTCPPacket processes a TCP packet |p| from |src|->|dst|, and emits the generated reply to Linux and/or MASQUE.
func processTCPPacket(src uint32, sport uint16, dst uint32, dstIP net.IP, dport uint16, p []byte) {
	seq := uint64(uint32(p[TCP_SEQ_NUM])<<24 | uint32(p[TCP_SEQ_NUM+1])<<16 | uint32(p[TCP_SEQ_NUM+2])<<8 | uint32(p[TCP_SEQ_NUM+3]))
	ack := uint64(uint32(p[TCP_ACK_NUM])<<24 | uint32(p[TCP_ACK_NUM+1])<<16 | uint32(p[TCP_ACK_NUM+2])<<8 | uint32(p[TCP_ACK_NUM+3]))
	rwin := uint16(p[TCP_WINDOW])<<8 | uint16(p[TCP_WINDOW+1])

	flow := activeTCPFlows[sport]

	// Handle initial SYN.
	if (p[TCP_FLAGS] & FLAG_BIT_SYN) == FLAG_BIT_SYN {
		if flow != nil {
			// SYN-ACK already received, ignore.
			return
		}
		pendingTCPSYNsMutex.Lock()
		if _, ok := pendingTCPSYNs[sport]; ok {
			// SYN-ACK already received, ignore.
			pendingTCPSYNsMutex.Unlock()
			return
		}

		// Process TCP options to find the window scale, if present.
		var windowScale uint8 = 0
		if (p[TCP_DATA_OFF] >> 4) > 0x05 {
			dataOffset := (p[TCP_DATA_OFF] >> 4) * 4
			startOptions := TCP_OPTIONS
			for i := startOptions; i < int(dataOffset); {
				optionType := p[i]
				if optionType == 0x00 {
					break
				}
				if optionType == 0x01 {
					i++
					continue
				}
				optionLength := p[i+1]
				if optionType == 0x03 {
					windowScale = p[i+2]
				}
				i += int(optionLength)
			}
		}

		flow := &TCPFlow{src: src, sport: sport, dst: dst, dport: dport, seq: 0, ack: uint32(seq + 1), rwin: int32(rwin), rwinScale: windowScale}
		pendingTCPSYNs[sport] = flow
		pendingTCPSYNsMutex.Unlock()

		dstIPCopy := [4]byte{}
		copy(dstIPCopy[:], dstIP[:])
		go setupMasque(dstIPCopy[:], flow)

		return
	}

	// If we don't have a flow, or were asked to close a flow or other weird things, reset it.
	if flow == nil || flow.garbageCollect || (p[TCP_FLAGS]&FLAG_BIT_FIN) != 0 || (p[TCP_FLAGS]&FLAG_BIT_RST) != 0 || (p[TCP_FLAGS]&FLAG_BIT_URG) != 0 {
		var replyseq, replyack uint32

		if flow != nil {
			fseq := atomic.LoadUint32(&flow.seq)
			fack := atomic.LoadUint32(&flow.ack)
			replyseq, replyack = fseq, fack
		} else {
			replyseq, replyack = 0, uint32(seq+1)
		}

		buf := replyRst(src, dst, sport, dport, replyseq, replyack)

		if err := pseudoSendToLinux(buf[:]); err != nil {
			logger.Error("Error in pseudoSendToLinux", "err", err)
		}

		// Remove any existing flow entry.
		if flow != nil {
			if err := flow.proxyConn.Close(); err != nil {
				logger.Error("Error closing flow.proxyConn", "err", err)
			}
			// If we're the ones initiating the close, this will signal to the masque -> linux goroutine to stop on its next iteration.
			flow.garbageCollect = true
			activeTCPFlows[sport] = nil
		}
		return
	}

	// Handle normal data segments.
	// Write the data to the writer that wants data for this TCP flow.
	dataoffset := ((p[TCP_DATA_OFF] & 0xF0) >> 4) << 2
	datalen := len(p) - int(dataoffset)

	fseq := atomic.LoadUint32(&flow.seq)
	fack := atomic.LoadUint32(&flow.ack)

	availableWindow := int32(rwin) << flow.rwinScale
	var diffAckSeq uint32
	if fseq < uint32(ack) {
		if (uint32(ack) - fseq) > (math.MaxUint32 >> 1) {
			diffAckSeq = uint32(uint64(fseq) + math.MaxUint32 - ack)
			logger.Debug("handling wrap around of diffAckSeq", "fseq", fseq, "ack", ack, "diffAckSeq", diffAckSeq)
		} else {
			// It's possible we see an ack before we've updated the local fseq because these are processed in parallel.
			// In that case, we should conservatively treat it as if the rwin is current.
			logger.Debug("handling ack ahead of fseq for diffAckSeq, setting to zero", "fseq", fseq, "ack", ack)
			diffAckSeq = 0
		}
	} else {
		diffAckSeq = fseq - uint32(ack)
	}

	if diffAckSeq > 0 {
		logger.Debug("nonzero difference between seq and ack", "diffAckSeq", diffAckSeq, "availableWindow", availableWindow)
		availableWindow -= int32(diffAckSeq)
		if availableWindow < 0 {
			logger.Warn("may have negative availableWindow, setting to zero", "availableWindow", availableWindow)
			availableWindow = 0
		}
	}
	atomic.StoreInt32(&flow.rwin, availableWindow)

	if datalen > 0 && uint32(seq) == fack {
		amountToAck := datalen

		n, err := flow.proxyConn.Write(p[dataoffset:])
		if err != nil {
			if err != io.ErrShortWrite {
				logger.Error("Error writing received bytes to writer", "err", err)

				// TODO: close/clean up any masque state held by this flow entry.

				// Reset the connection
				// TODO: verify that this is the right sequence numbering expected by the other side for such a reset.
				buf := replyRst(src, dst, sport, dport, fseq, fack)

				if err := pseudoSendToLinux(buf[:]); err != nil {
					logger.Error("Error in pseudoSendToLinux", "err", err)
				}

				activeTCPFlows[sport] = nil
				flow.garbageCollect = true

				return
			} else {
				amountToAck = n
			}
		}

		// Update what we are ACKing and send the ACK.
		atomic.StoreUint32(&flow.ack, uint32(seq+uint64(amountToAck)))
		fack = atomic.LoadUint32(&flow.ack)

		buf := replyAck(src, dst, sport, dport, fseq, fack)

		if err := pseudoSendToLinux(buf[:]); err != nil {
			logger.Error("Error in pseudoSendToLinux", "err", err)
		}

	} else {
		// got a raw ack
		logger.Debug("Got raw ack", "fseq", fseq, "ack", ack, "rwin", rwin)
	}
}

var udpPktCounter = 0

// processUDPPacket processes a UDP packet from Linux -> MASQUE.
func processUDPPacket(src uint32, sport uint16, dst uint32, dstIP net.IP, dport uint16, buf []byte) {
	// Special case for DNS.
	if dport == 53 {
		bufCopy := make([]byte, len(buf))
		copy(bufCopy, buf)
		go handleDNS(src, sport, dst, dport, bufCopy)
		return
	}

	flow, ok := activeUDPFlows[UDPFlowKey{src, sport, dst, dport}]
	if !ok {
		flow = &UDPFlow{src: src, sport: sport, dst: dst, dport: dport}
		if err := setupUDPMasque(dstIP, flow); err != nil {
			// TODO: add more robust error handling, since it's possible we're offline.
			// TODO: possibly attempt to reconnect to the proxy, and if that fails, make sure to signal that the VPN is down.
			logger.Error("Error setting up masque for flow", "err", err, "flow", flow)
			return
		}

		activeUDPFlows[UDPFlowKey{src, sport, dst, dport}] = flow
	}

	// Send the packet to MASQUE.
	_, err := flow.proxyConn.Write(buf[DEFAULT_UDP_HDR_SIZE:])
	if err != nil && err != io.ErrShortWrite {
		logger.Error("Error writing received bytes to writer", "err", err, "flow", flow)

		// TODO: close/clean up any masque state held by this flow entry.
		delete(activeUDPFlows, UDPFlowKey{src, sport, dst, dport})
		flow.garbageCollect = true
		err := flow.proxyConn.Close()
		if err != nil {
			logger.Error("Error in flow.proxyConn.Close()", "err", err, "flow", flow)
		}

		return
	}

	// Every 64K packets, clean up dead UDP flows in deadUDPFlows.
	udpPktCounter += 1
	if udpPktCounter&0xFFFF == 0 {
		for _, flow := range deadUDPFlows {
			if flow.garbageCollect {
				logger.Debug("Deleting dead UDP flow", "flow", flow)
				delete(activeUDPFlows, UDPFlowKey{flow.src, flow.sport, flow.dst, flow.dport})
			}
		}
		deadUDPFlows = deadUDPFlows[:0]
	}
}

// UserStackIPProcessPacket processes an IPv4 packet and emits the generated reply to Linux and/or MASQUE.
func UserStackIPProcessPacket(p []byte) {
	if !relayActive {
		return
	}

	// Before we do anything for this packet, check if there are any flows that have established in the meantime.
	processPendingTCPSYNs()

	ver := p[IP_VERSION_IHL] >> 4
	ihl := p[IP_VERSION_IHL] & 0x0F
	pktlen := uint16(p[IP_LEN])<<8 | uint16(p[IP_LEN+1])

	if ver != 4 {
		return
	}
	if int(pktlen) != len(p) {
		return
	}

	src := uint32(p[IP_SRC])<<24 | uint32(p[IP_SRC+1])<<16 | uint32(p[IP_SRC+2])<<8 | uint32(p[IP_SRC+3])
	dst := uint32(p[IP_DST])<<24 | uint32(p[IP_DST+1])<<16 | uint32(p[IP_DST+2])<<8 | uint32(p[IP_DST+3])

	proto := p[IP_PROTO]
	if proto != PROTO_TCP && proto != PROTO_UDP {
		return
	}

	if p[IP_DST] == WAKEUP_PACKET_IP_VALUE && p[IP_DST+1] == WAKEUP_PACKET_IP_VALUE && p[IP_DST+2] == WAKEUP_PACKET_IP_VALUE && p[IP_DST+3] == WAKEUP_PACKET_IP_VALUE {
		logger.Debug("Got wakeup packet, ignore.")
		return
	}

	l4hdr := p[(ihl << 2):]
	sport := uint16(l4hdr[TCP_SRC_PORT])<<8 | uint16(l4hdr[TCP_SRC_PORT+1])
	dport := uint16(l4hdr[TCP_DST_PORT])<<8 | uint16(l4hdr[TCP_DST_PORT+1])

	icmpCode := -1

	// Check that the IP/port are allowed.
	var disallowedIP bool = (p[IP_DST] == 10) ||
		(p[IP_DST] == 255 && p[IP_DST+1] == 255 && p[IP_DST+2] == 255 && p[IP_DST+3] == 255) ||
		(p[IP_DST] == 0 && p[IP_DST+1] == 0 && p[IP_DST+2] == 0 && p[IP_DST+3] == 0) ||
		(p[IP_DST] == 192 && p[IP_DST+1] == 168) ||
		(p[IP_DST] == 127) ||
		(p[IP_DST] == 172 && p[IP_DST+1]&0xf0 == 16) ||
		(p[IP_DST]&0xf0 == 0xe0) ||
		(p[IP_DST] == 224 && p[IP_DST+1] == 0 && p[IP_DST+2] == 0) ||
		(p[IP_DST] == 169 && p[IP_DST+1] == 254)

	logger.Debug("IP matches disallowed check", "p", p)
	if disallowedIP && ProhibitDisallowedIPPorts {
		icmpCode = 1 // host unreachable
	}

	isDns := proto == PROTO_UDP && dport == 53
	isProbablyDoT := proto == PROTO_TCP && dport == 853
	if isProbablyDoT {
		icmpCode = 3
	}
	if !isDns && icmpCode != -1 {
		buf := [ICMP_UNREACHABLE_SIZE]byte{}
		copy(buf[:], preBakedICMP[:])

		const icmpType = 3
		setIPHdr(buf[:], dst, src, uint16(ICMP_UNREACHABLE_SIZE))
		setICMPHdr(buf[DEFAULT_IP_HDR_SIZE:], uint8(icmpType), uint8(icmpCode), uint16(0))
		copy(buf[DEFAULT_IP_HDR_SIZE+DEFAULT_ICMP_UNREACHABLE_HDR_SIZE:], p[:DEFAULT_IP_HDR_SIZE+DEFAULT_UDP_HDR_SIZE])
		setIPandL4Checksum(buf[:], PROTO_ICMP)

		if err := pseudoSendToLinux(buf[:]); err != nil {
			logger.Error("Error in pseudoSendToLinux", "err", err)
		}

		return
	}

	if proto == PROTO_TCP {
		processTCPPacket(src, sport, dst, p[IP_DST:IP_DST+4], dport, l4hdr)
	} else if proto == PROTO_UDP {
		processUDPPacket(src, sport, dst, p[IP_DST:IP_DST+4], dport, l4hdr)
	}
}

// pseudoSendToLinux sends a packet to Android/Linux.
func pseudoSendToLinux(p []byte) error {
	if !relayActive {
		return errors.New("relay is not active")
	}

	err := toLinux(p, len(p))
	if err != nil {
		packet := gopacket.NewPacket(p[:], layers.LayerTypeIPv4, gopacket.Default)
		logger.Error("Error sending packet to Linux", "err", err, "packet", packet)
		return err
	}

	return nil
}
