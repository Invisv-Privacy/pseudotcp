package pseudotcp

import "net"

// IP protocol numbers for L4 headers.
const (
	// PROTO_ICMP is the IP protocol number for ICMP
	PROTO_ICMP byte = 1
	// PROTO_TCP is the IP protocol number for TCP
	PROTO_TCP byte = 6
	// PROTO_UDP is the IP protocol number for UDP
	PROTO_UDP byte = 17
)

// Byte offsets for IPv4 header fields.
const (
	IP_VERSION_IHL int = 0
	IP_LEN         int = 2
	IP_TTL         int = 8
	IP_PROTO       int = 9
	IP_CHECK       int = 10
	IP_SRC         int = 12
	IP_DST         int = 16
)

// Byte offsets for TCP header fields.
const (
	TCP_SRC_PORT int = 0
	TCP_DST_PORT int = 2
	TCP_SEQ_NUM  int = 4
	TCP_ACK_NUM  int = 8
	TCP_DATA_OFF int = 12
	TCP_FLAGS    int = 13
	TCP_WINDOW   int = 14
	TCP_CHECK    int = 16
	TCP_OPTIONS  int = 20
)

// TCP flag bits.
const (
	FLAG_BIT_URG byte = 0x20
	FLAG_BIT_ACK byte = 0x10
	FLAG_BIT_PSH byte = 0x08
	FLAG_BIT_RST byte = 0x04
	FLAG_BIT_SYN byte = 0x02
	FLAG_BIT_FIN byte = 0x01
)

// Byte offsets for UDP header fields.
const (
	UDP_SRC_PORT int = 0
	UDP_DST_PORT int = 2
	UDP_LEN      int = 4
	UDP_CHECK    int = 6
)

// Byte offsets for ICMP header fields.
const (
	ICMP_TYPE         int = 0
	ICMP_CODE         int = 1
	ICMP_CHECK        int = 2
	ICMP_NEXT_HOP_MTU     = 6
)

// Header size constants.
const (
	// DEFAULT_IP_HDR_SIZE is the size of a standard IPv4 header
	DEFAULT_IP_HDR_SIZE int = 20
	// DEFAULT_TCP_HDR_SIZE is the size of a standard TCP header
	DEFAULT_TCP_HDR_SIZE int = 20
	// DEFAULT_UDP_HDR_SIZE is the size of a standard UDP header
	DEFAULT_UDP_HDR_SIZE int = 8
	// DEFAULT_ICMP_UNREACHABLE_HDR_SIZE is the size of an ICMP unreachable message header
	DEFAULT_ICMP_UNREACHABLE_HDR_SIZE int = 8
	// SYNACK_SIZE is the total size of a SYN-ACK packet
	SYNACK_SIZE = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE + 4
	// RST_SIZE is the total size of a RST packet
	RST_SIZE = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE
	// ACK_SIZE is the total size of an ACK packet
	ACK_SIZE = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE
	// ICMP_UNREACHABLE_SIZE is the total size of an ICMP unreachable message
	ICMP_UNREACHABLE_SIZE = DEFAULT_IP_HDR_SIZE + DEFAULT_ICMP_UNREACHABLE_HDR_SIZE + (DEFAULT_IP_HDR_SIZE + 8)
)

// Pre-baked packets that have common fields set and the rest of the headers set to defaults or zero.
var (
	preBakedSynAck  [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE + 4]byte // extra 4 bytes for WSopt
	preBakedAck     [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte
	preBakedRst     [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte
	preBakedSegment [DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE]byte

	preBakedUDP [DEFAULT_IP_HDR_SIZE + DEFAULT_UDP_HDR_SIZE]byte

	preBakedICMP [DEFAULT_IP_HDR_SIZE + DEFAULT_ICMP_UNREACHABLE_HDR_SIZE]byte
)

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

// replyInitialSyn creates a SYN-ACK reply to an initial SYN and returns the generated SYN-ACK.
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
