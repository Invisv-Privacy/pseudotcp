package pseudotcp

// IP protocol numbers for L4 headers.
const (
	PROTO_ICMP byte = 1
	PROTO_TCP  byte = 6
	PROTO_UDP  byte = 17
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
	DEFAULT_IP_HDR_SIZE               int = 20
	DEFAULT_TCP_HDR_SIZE              int = 20
	DEFAULT_UDP_HDR_SIZE              int = 8
	DEFAULT_ICMP_UNREACHABLE_HDR_SIZE int = 8
	SYNACK_SIZE                           = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE + 4
	RST_SIZE                              = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE
	ACK_SIZE                              = DEFAULT_IP_HDR_SIZE + DEFAULT_TCP_HDR_SIZE
	ICMP_UNREACHABLE_SIZE                 = DEFAULT_IP_HDR_SIZE + DEFAULT_ICMP_UNREACHABLE_HDR_SIZE + (DEFAULT_IP_HDR_SIZE + 8)
)
