package pseudotcp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProxyClient interface {
	Connect() error
	CurrentProxyIP() string
	CreateTCPStream(string) (io.ReadWriteCloser, error)
	CreateUDPStream(string) (io.ReadWriteCloser, error)
	Close() error
}

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

// Protect overrides Android's VpnService.protect()
// Arguments:
// fileDescriptor is a system file descriptor to protect from the VPN
type SocketProtector func(fileDescriptor int) error

type SendPacket func(packet []byte, length int) error

const (
	// MTU of the TUN interface we're using, has to match Android.
	TUN_MTU                   = 32000
	INTERNET_MTU              = 1500
	DNS_CACHE_TIMEOUT_SECONDS = 300
	DEFAULT_PROXY_PORT        = "443"
)

const (
	WAKEUP_PACKET_IP_PORT  string = "10.10.10.10:1234" // Invalid destination for the wakeup packet.
	WAKEUP_PACKET_IP_VALUE byte   = 10
)

type PseudoTCP struct {
	// proxyClient is generally a masque proxy client though it can be any struct satisfying the ProxyClient interface,
	// ie that it can create TCP and UDP streams to specified endpoints
	proxyClient ProxyClient

	// active indicates whether we can process packets.
	active bool

	// activeUDPFlows stores a mapping from client (src) IP/port and server (dst) IP/port to the flow structure for UDP flows.
	activeUDPFlows map[UDPFlowKey]*UDPFlow

	// deadUDPFlows stores a list of UDP flows that have been closed.
	deadUDPFlows []*UDPFlow

	// currentProtect is the current function to be called to socket protect for the VPN
	currentProtect SocketProtector

	dnsClient *dnsClientState

	// toLinux is the function for sending packets to the linux stack
	toLinux SendPacket

	logger *slog.Logger

	// activeTCPFlows stores a mapping from client port to the flow structure for TCP flows.
	activeTCPFlows [65536]*TCPFlow

	// pendingTCPSYNs stores a mapping from client port to the flow structure for TCP flows while we're waiting for the proxy server to reply.
	pendingTCPSYNs      map[uint16]*TCPFlow
	pendingTCPSYNsMutex sync.Mutex

	// establishedTCPFlows channel of TCP flows whose connection establishment has completed.
	establishedTCPFlows      chan *TCPFlow
	establishedTCPFlowsCount int32

	// wakeupUDPConn is used by established TCP flow goroutines to wake up the datapath to process them.
	wakeupUDPConn net.Conn

	udpPktCounter int

	// prohibitDisallowedIPPorts determines whether we check if packets are heading to an "allowed IP/Port" tuple
	// And if we should prohibit them w/ a host unreachable code
	prohibitDisallowedIPPorts bool

	// configuredDoHServers is the list of servers we were configured to use.
	// This list is copied to activeDoHServers when the relay is started.
	// If this is empty, we use the default list.
	configuredDoHServers []string

	// activeDoHServers is the list of servers currently in use.
	activeDoHServers []string
}

type PseudoTCPConfig struct {
	Logger *slog.Logger

	ProxyClient ProxyClient

	SendPacket SendPacket

	ProhibitDisallowedIPPorts bool
}

func NewPseudoTCP(config *PseudoTCPConfig) *PseudoTCP {
	// TODO: Either sane defaults or return an error here

	var l *slog.Logger
	// TODO: replace with DiscardHandler when accepted
	// https://github.com/golang/go/issues/62005
	if config.Logger != nil {
		l = config.Logger
	} else {
		l = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	return &PseudoTCP{
		logger:                    l.With("config", config),
		toLinux:                   config.SendPacket,
		prohibitDisallowedIPPorts: config.ProhibitDisallowedIPPorts,

		proxyClient: config.ProxyClient,

		pendingTCPSYNs:      make(map[uint16]*TCPFlow),
		establishedTCPFlows: make(chan *TCPFlow),
	}
}

// Init initializes the userspace network stack module. This must be called before any other UserStack function.
func (t *PseudoTCP) Init() error {
	t.logger.Debug("Initializing")

	if t.toLinux == nil {
		return errors.New("toLinux is nil")
	}

	t.initActiveFlows()
	preBakePackets()
	if err := t.initWakeupUDPConn(); err != nil {
		t.logger.Error("Error in initWakeupUDPConn", "err", err)
	}

	err := t.proxyClient.Connect()
	if err != nil {
		t.active = false
		t.logger.Error("failed connecting to proxy", "err", err)
		return err
	}

	t.initDnsClient()

	t.active = true
	return nil
}

func (t *PseudoTCP) Send(packetData []byte) {
	t.UserStackIPProcessPacket(packetData)
}

func (t *PseudoTCP) SetLogger(l *slog.Logger) {
	t.logger = l
}

func (t *PseudoTCP) clearActiveTCPFlows() {
	for i := range t.activeTCPFlows {
		if t.activeTCPFlows[i] != nil {
			t.activeTCPFlows[i].garbageCollect = true
			if err := t.activeTCPFlows[i].proxyConn.Close(); err != nil {
				t.logger.Error("Error calling activeTCPFlows[i].proxyConn.Close()", "err", err, "activeTCPFlows[i]", t.activeTCPFlows[i])
			}
		}
		t.activeTCPFlows[i] = nil
	}
}

func (t *PseudoTCP) initActiveFlows() {
	if t.activeUDPFlows != nil {
		t.terminateActiveFlows()
	}
	t.clearActiveTCPFlows()
	t.activeUDPFlows = make(map[UDPFlowKey]*UDPFlow)
	t.deadUDPFlows = make([]*UDPFlow, 0)

	if err := t.proxyClient.Close(); err != nil {
		t.logger.Error("Error closing proxyClient", "err", err)
	}
}

func (t *PseudoTCP) terminateActiveFlows() {
	for _, flow := range t.activeUDPFlows {
		flow.garbageCollect = true
		err := flow.proxyConn.Close()
		if err != nil {
			t.logger.Error("Error calling flow.proxyConn.Close()", "err", err, "flow.proxyConn", flow.proxyConn)
		}
	}
	t.clearActiveTCPFlows()
	t.activeUDPFlows = nil
	t.deadUDPFlows = nil
}

// setupMasque initiates a MASQUE connection via an already-connected proxy to flow.dst:flow.dport.
// It also starts a goroutine to handle the MASQUE connection, by reading data from it and injecting that data as TCP segments.
func (t *PseudoTCP) setupMasque(dstIP net.IP, flow *TCPFlow) {
	host := fmt.Sprintf("%v:%v", dstIP, flow.dport)

	t.logger.Info("Connecting TCP", "host", host)
	if c, err := t.proxyClient.CreateTCPStream(host); err != nil {
		// TODO: add more robust error handling, since it's possible we're offline.
		// TODO: possibly attempt to reconnect to the proxy, and if that fails, make sure to signal that the VPN is down.
		t.logger.Error("Error setting up masque for flow", "err", err, "host", host)
		t.pendingTCPSYNsMutex.Lock()
		delete(t.pendingTCPSYNs, flow.sport)
		t.pendingTCPSYNsMutex.Unlock()
		return
	} else {
		t.logger.Info("Connected", "host", host)
		flow.proxyConn = c
	}

	go func() {
		t.establishedTCPFlows <- flow // blocks because establishedTCPFlows is an unbuffered channel

		// This Lock()/Unlock() prevents us from starting the goroutine until the SYNACK is sent, because the outbound thread will have the lock.
		// The unbuffered channel functions as one lock (really a semaphore), because this function can't proceed until the select in the outbound thread.
		// When that select takes place, the outbound thread holds the other lock (pendingTCPSYNsMutex),
		// so this (and any other worker goroutine) can't actually start until the outbound thread has finished its work of marking all pending flows as active.
		//
		// TODO: consider changing establishedTCPFlows to take {flow,signalingChannel} to signal that the outbound thread has finished its work, and then this goroutine can start.
		t.pendingTCPSYNsMutex.Lock()
		//nolint:staticcheck
		t.pendingTCPSYNsMutex.Unlock()
		t.logger.Debug("setupMasque goroutine started for flow", "flow", flow)

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

				err := t.pseudoSendToLinux(buf[:totalHdrLen])
				if err != nil {
					t.logger.Error("Error sending dummy segment to Linux", "err", err)
				}

				t.logger.Debug("flow rwin limited too much, sleeping")
				time.Sleep(100 * time.Millisecond)

				dummyPacketToggle = false
				continue
			}
			dummyPacketToggle = true

			// If the receiver has very little receive window left, choose a safe packet size.
			if rwin < (3 * TUN_MTU) {
				runtime.Gosched() // yield to allow the inbound thread to process an ACK
				targetReadLen = SAFE_PACKET_SIZE
				t.logger.Debug("adjusting targetReadLen, based on rwin", "targetReadLen", targetReadLen, "rwin", rwin)
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
				err = t.pseudoSendToLinux(buf[:pktsize])

				if err == nil && pktsize > (TUN_MTU>>1) {
					t.logger.Debug("Successful send above half MTU", "pktsize", pktsize)
				}
				if err != nil && strings.Contains(err.Error(), "ENOBUFS") {
					t.logger.Warn("Got ENOBUFS, splitting packet")

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

					t.logger.Debug("Sending split packet")
					err = t.pseudoSendToLinux(buf[:pktsize1])
					if err == nil {
						err = t.pseudoSendToLinux(buf2[:pktsize2])
						if err == nil {
							// shrink buf and buf2 to half their current size
							buf = buf[:len(buf)>>1]
							buf2 = buf2[:len(buf2)>>1]
							t.logger.Debug("Shrank buf and buf2", "len(buf)", len(buf), "len(buf2)", len(buf2))
						}
					}
					if err != nil {
						t.logger.Error("Failed to send split packet", "err", err)
					}
				} else if err != nil {
					t.logger.Error("Failure sending packet", "err", err)
				}

				atomic.AddInt32(&flow.rwin, int32(-n))
			}

			if err != nil {
				t.logger.Error("Error reading from port", "flow.sport", flow.sport, "err", err, "flow", flow)
				flow.garbageCollect = true
				err := flow.proxyConn.Close()
				if err != nil {
					t.logger.Error("Error in flow.proxyConn.Close()", "err", err, "flow.proxyConn", flow.proxyConn)
				}
			}
		}

		// TODO: Close / cleanup the masque connection.
	}()

	atomic.AddInt32(&t.establishedTCPFlowsCount, 1)
	t.logger.Debug("setupMasque about to send wakeup")
	_, err := t.wakeupUDPConn.Write([]byte{0x00})
	if err != nil {
		t.logger.Error("Error writing to wakeup UDP socket", "err", err)
	}
}

// setupUDPMasque initiates a UDP MASQUE connection via an already-connected proxy to flow.dst:flow.dport.
// It also starts a goroutine to handle the UDP MASQUE connection, sending datagrams to Linux.
func (t *PseudoTCP) setupUDPMasque(dstIP net.IP, flow *UDPFlow) error {
	host := fmt.Sprintf("%v:%v", dstIP, flow.dport)

	t.logger.Debug("Connecting UDP", "host", host)
	if c, err := t.proxyClient.CreateUDPStream(host); err != nil {
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

				err := t.pseudoSendToLinux(buf[:pktsize])
				if err != nil {
					t.logger.Error("Error in pseudoSendToLinux", "err", err, "flow", flow)
				}
			}

			if err != nil {
				t.logger.Error("Error reading from port", "flow.sport", flow.sport, "err", err, "flow", flow)
				flow.garbageCollect = true
				// append this flow to deadUDPFlows
				t.deadUDPFlows = append(t.deadUDPFlows, flow)
			}
		}

		// TODO: Close / cleanup the masque connection.
	}()
	return nil
}

// CurrentProxyIP returns the IP of the Proxy A server we are connected to.
// If relay is not active, returns empty string.
func (t *PseudoTCP) CurrentProxyIP() string {
	if t.active {
		return t.proxyClient.CurrentProxyIP()
	}
	return ""
}

func (t *PseudoTCP) initWakeupUDPConn() error {
	// TODO: clean up wakeupUDPConn from before.

	var err error
	t.wakeupUDPConn, err = net.Dial("udp4", WAKEUP_PACKET_IP_PORT)
	if err != nil {
		return err
	}
	return nil
}

// ReconnectToProxy indicates to the Relay code that it should try to connect to the proxy again.
// This is good to call when Android detects that a network interface has come back up.
func (t *PseudoTCP) ReconnectToProxy() error {
	t.active = false
	t.initActiveFlows()

	err := t.proxyClient.Connect()
	if err != nil {
		t.active = false
		t.logger.Error("failed connecting to proxy", "err", err)
		return err
	}

	t.initDnsClient()

	t.active = true
	return nil
}

func (t *PseudoTCP) Shutdown() {
	t.active = false
	t.terminateActiveFlows()
	if err := t.proxyClient.Close(); err != nil {
		t.logger.Error("Error closing proxyClient", "err", err)
	}
}

func (t *PseudoTCP) processPendingTCPSYNs() {
	waitingFlows := atomic.LoadInt32(&t.establishedTCPFlowsCount)
	if waitingFlows > 0 {
		t.pendingTCPSYNsMutex.Lock()
		defer t.pendingTCPSYNsMutex.Unlock()
		for {
			select {
			case flow := <-t.establishedTCPFlows:
				delete(t.pendingTCPSYNs, flow.sport)
				buf := replyInitialSyn(flow.src, flow.dst, flow.sport, flow.dport, flow.seq, flow.ack)
				flow.seq += 1
				t.activeTCPFlows[flow.sport] = flow

				if err := t.pseudoSendToLinux(buf[:]); err != nil {
					t.logger.Error("Error in pseudoSendToLinux", "err", err)
				}

				atomic.AddInt32(&t.establishedTCPFlowsCount, -1)
			default:
				return
			}
		}
	}
}

// processTCPPacket processes a TCP packet |p| from |src|->|dst|, and emits the generated reply to Linux and/or MASQUE.
func (t *PseudoTCP) processTCPPacket(src uint32, sport uint16, dst uint32, dstIP net.IP, dport uint16, p []byte) {
	seq := uint64(uint32(p[TCP_SEQ_NUM])<<24 | uint32(p[TCP_SEQ_NUM+1])<<16 | uint32(p[TCP_SEQ_NUM+2])<<8 | uint32(p[TCP_SEQ_NUM+3]))
	ack := uint64(uint32(p[TCP_ACK_NUM])<<24 | uint32(p[TCP_ACK_NUM+1])<<16 | uint32(p[TCP_ACK_NUM+2])<<8 | uint32(p[TCP_ACK_NUM+3]))
	rwin := uint16(p[TCP_WINDOW])<<8 | uint16(p[TCP_WINDOW+1])

	flow := t.activeTCPFlows[sport]

	// Handle initial SYN.
	if (p[TCP_FLAGS] & FLAG_BIT_SYN) == FLAG_BIT_SYN {
		if flow != nil {
			// SYN-ACK already received, ignore.
			return
		}
		t.pendingTCPSYNsMutex.Lock()
		if _, ok := t.pendingTCPSYNs[sport]; ok {
			// SYN-ACK already received, ignore.
			t.pendingTCPSYNsMutex.Unlock()
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
		t.pendingTCPSYNs[sport] = flow
		t.pendingTCPSYNsMutex.Unlock()

		dstIPCopy := [4]byte{}
		copy(dstIPCopy[:], dstIP[:])
		go t.setupMasque(dstIPCopy[:], flow)

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

		if err := t.pseudoSendToLinux(buf[:]); err != nil {
			t.logger.Error("Error in pseudoSendToLinux", "err", err)
		}

		// Remove any existing flow entry.
		if flow != nil {
			if err := flow.proxyConn.Close(); err != nil {
				t.logger.Error("Error closing flow.proxyConn", "err", err)
			}
			// If we're the ones initiating the close, this will signal to the masque -> linux goroutine to stop on its next iteration.
			flow.garbageCollect = true
			t.activeTCPFlows[sport] = nil
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
			t.logger.Debug("handling wrap around of diffAckSeq", "fseq", fseq, "ack", ack, "diffAckSeq", diffAckSeq)
		} else {
			// It's possible we see an ack before we've updated the local fseq because these are processed in parallel.
			// In that case, we should conservatively treat it as if the rwin is current.
			t.logger.Debug("handling ack ahead of fseq for diffAckSeq, setting to zero", "fseq", fseq, "ack", ack)
			diffAckSeq = 0
		}
	} else {
		diffAckSeq = fseq - uint32(ack)
	}

	if diffAckSeq > 0 {
		t.logger.Debug("nonzero difference between seq and ack", "diffAckSeq", diffAckSeq, "availableWindow", availableWindow)
		availableWindow -= int32(diffAckSeq)
		if availableWindow < 0 {
			t.logger.Warn("may have negative availableWindow, setting to zero", "availableWindow", availableWindow)
			availableWindow = 0
		}
	}
	atomic.StoreInt32(&flow.rwin, availableWindow)

	if datalen > 0 && uint32(seq) == fack {
		amountToAck := datalen

		n, err := flow.proxyConn.Write(p[dataoffset:])
		if err != nil {
			if err != io.ErrShortWrite {
				t.logger.Error("Error writing received bytes to writer", "err", err)

				// TODO: close/clean up any masque state held by this flow entry.

				// Reset the connection
				// TODO: verify that this is the right sequence numbering expected by the other side for such a reset.
				buf := replyRst(src, dst, sport, dport, fseq, fack)

				if err := t.pseudoSendToLinux(buf[:]); err != nil {
					t.logger.Error("Error in pseudoSendToLinux", "err", err)
				}

				t.activeTCPFlows[sport] = nil
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

		if err := t.pseudoSendToLinux(buf[:]); err != nil {
			t.logger.Error("Error in pseudoSendToLinux", "err", err)
		}

	} else {
		// got a raw ack
		t.logger.Debug("Got raw ack", "fseq", fseq, "ack", ack, "rwin", rwin)
	}
}

// processUDPPacket processes a UDP packet from Linux -> MASQUE.
func (t *PseudoTCP) processUDPPacket(src uint32, sport uint16, dst uint32, dstIP net.IP, dport uint16, buf []byte) {
	// Special case for DNS.
	if dport == 53 {
		bufCopy := make([]byte, len(buf))
		copy(bufCopy, buf)
		go t.handleDNS(src, sport, dst, dport, bufCopy)
		return
	}

	flow, ok := t.activeUDPFlows[UDPFlowKey{src, sport, dst, dport}]
	if !ok {
		flow = &UDPFlow{src: src, sport: sport, dst: dst, dport: dport}
		if err := t.setupUDPMasque(dstIP, flow); err != nil {
			// TODO: add more robust error handling, since it's possible we're offline.
			// TODO: possibly attempt to reconnect to the proxy, and if that fails, make sure to signal that the VPN is down.
			t.logger.Error("Error setting up masque for flow", "err", err, "flow", flow)
			return
		}

		t.activeUDPFlows[UDPFlowKey{src, sport, dst, dport}] = flow
	}

	// Send the packet to MASQUE.
	_, err := flow.proxyConn.Write(buf[DEFAULT_UDP_HDR_SIZE:])
	if err != nil && err != io.ErrShortWrite {
		t.logger.Error("Error writing received bytes to writer", "err", err, "flow", flow)

		// TODO: close/clean up any masque state held by this flow entry.
		delete(t.activeUDPFlows, UDPFlowKey{src, sport, dst, dport})
		flow.garbageCollect = true
		err := flow.proxyConn.Close()
		if err != nil {
			t.logger.Error("Error in flow.proxyConn.Close()", "err", err, "flow", flow)
		}

		return
	}

	// Every 64K packets, clean up dead UDP flows in deadUDPFlows.
	t.udpPktCounter += 1
	if t.udpPktCounter&0xFFFF == 0 {
		for _, flow := range t.deadUDPFlows {
			if flow.garbageCollect {
				t.logger.Debug("Deleting dead UDP flow", "flow", flow)
				delete(t.activeUDPFlows, UDPFlowKey{flow.src, flow.sport, flow.dst, flow.dport})
			}
		}
		t.deadUDPFlows = t.deadUDPFlows[:0]
	}
}

// UserStackIPProcessPacket processes an IPv4 packet and emits the generated reply to Linux and/or MASQUE.
func (t *PseudoTCP) UserStackIPProcessPacket(p []byte) {
	if !t.active {
		return
	}

	// Before we do anything for this packet, check if there are any flows that have established in the meantime.
	t.processPendingTCPSYNs()

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
		t.logger.Debug("Got wakeup packet, ignore.")
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

	t.logger.Debug("IP matches disallowed check", "p", p)
	if disallowedIP && t.prohibitDisallowedIPPorts {
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

		if err := t.pseudoSendToLinux(buf[:]); err != nil {
			t.logger.Error("Error in pseudoSendToLinux", "err", err)
		}

		return
	}

	if proto == PROTO_TCP {
		t.processTCPPacket(src, sport, dst, p[IP_DST:IP_DST+4], dport, l4hdr)
	} else if proto == PROTO_UDP {
		t.processUDPPacket(src, sport, dst, p[IP_DST:IP_DST+4], dport, l4hdr)
	}
}

// pseudoSendToLinux sends a packet to Android/Linux.
func (t *PseudoTCP) pseudoSendToLinux(p []byte) error {
	if !t.active {
		return errors.New("relay is not active")
	}

	err := t.toLinux(p, len(p))
	if err != nil {
		packet := gopacket.NewPacket(p[:], layers.LayerTypeIPv4, gopacket.Default)
		t.logger.Error("Error sending packet to Linux", "err", err, "packet", packet)
		return err
	}

	return nil
}
