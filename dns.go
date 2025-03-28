package pseudotcp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// DNSResponse represents the structure of a DNS-over-HTTPS response in JSON format.
type DNSResponse struct {
	// Answer contains the DNS records returned in the response
	Answer []struct {
		// Name is the domain name for this record
		Name string `json:"name"`
		// Type is the DNS record type (1 for A, 28 for AAAA, etc.)
		Type int `json:"type"`
		// TTL is the time-to-live for this record in seconds
		TTL int `json:"ttl"`
		// Data is the record data (IP address for A/AAAA records, etc.)
		Data string `json:"data"`
	} `json:"Answer"`
}

type dnsCacheEntry struct {
	result  *dns.Msg
	created time.Time
}

type dnsClientState struct {
	h2Transport *http2.Transport
	cache       map[string]*dnsCacheEntry // maps from Question to dnsCacheEntry
	mu          sync.RWMutex
}

// The default DNS-over-HTTPS server to use for DNS queries.
var DEFAULT_DOH_SERVER_ADDRS = []string{"1.1.1.1:443", "1.0.0.1:443", "1.1.1.2:443", "1.0.0.2:443"}
var DEFAULT_POPULAR_DNS_NAMES []string = []string{"api.invisv.com"}

func (t *PseudoTCP) ResolveDOHJSON(host string) (string, error) {
	var d net.Dialer
	d.Control = t.dialerControlProtect()

	tr := &http2.Transport{
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			t := &tls.Dialer{NetDialer: &d, Config: &tls.Config{NextProtos: []string{"h2"}}}
			return t.Dial("tcp", addr)
		},
		AllowHTTP: true,
	}

	reader, writer := io.Pipe()
	req, err := http.NewRequest("GET", "https://1.1.1.1/dns-query?name="+host, reader)
	if err != nil {
		t.logger.Error("Error creating DNS request", "err", err, "host", host)
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	response, err := tr.RoundTrip(req)
	if err != nil {
		t.logger.Error("Error sending DNS request", "err", err, "req", req)
		return "", err
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			t.logger.Error("Error closing body", "err", err)
		}
	}()

	err = writer.Close()
	if err != nil {
		t.logger.Error("Error closing writer", "err", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.logger.Error("Error reading DNS response", "err", err, "response", response)
		return "", err
	}

	t.logger.Debug("DNS response", "body", string(body))
	dnsResponse := DNSResponse{}
	err = json.Unmarshal(body, &dnsResponse)
	if err != nil {
		t.logger.Error("Error unmarshalling DNS response", "err", err, "dnsresponse", dnsResponse)
		return "", err
	}
	t.logger.Debug("DNS response", "dnsResponse", dnsResponse)
	for _, answer := range dnsResponse.Answer {
		if answer.Type == 1 {
			t.logger.Debug("DNS response Type 1", "answer.Data", answer.Data)
			return answer.Data, nil
		}
	}
	return "", errors.New("no A record found")
}

// initDNSClient initializes the DNS client.
func (t *PseudoTCP) initDnsClient() {
	t.dnsClient = &dnsClientState{
		h2Transport: &http2.Transport{AllowHTTP: false,
			DisableCompression: true,
		},
		cache: make(map[string]*dnsCacheEntry),
	}

	if len(t.configuredDoHServers) > 0 {
		t.activeDoHServers = make([]string, len(t.configuredDoHServers))
		copy(t.activeDoHServers, t.configuredDoHServers)
	} else {
		t.activeDoHServers = make([]string, len(DEFAULT_DOH_SERVER_ADDRS))
		copy(t.activeDoHServers, DEFAULT_DOH_SERVER_ADDRS)
	}

	go t.precachePopularDnsDomains()
}

func (t *PseudoTCP) precachePopularDnsDomains() {
	for _, domain := range DEFAULT_POPULAR_DNS_NAMES {
		if _, err := net.LookupHost(domain); err != nil {
			t.logger.Error("Error looking up host", "err", err, "domain", domain)
		}
	}
}

// handleDNS translates a normal DNS query/response packet into
// a DoT query/response packet, and sends it to a DNS-over-HTTPS service.
// Operation details:
// client -> dns: create an HTTPS connection to <dns server>:443, and
// send the UDP packet payload;
// dns -> client: receive DNS response packet(s) from the HTTPS
// connection, craft a raw UDP packet and send it back to Android.
func (t *PseudoTCP) handleDNS(src uint32, sport uint16, dst uint32, dport uint16, buf []byte) {
	dnsStart := time.Now()

	dnsReq := new(dns.Msg)
	err := dnsReq.Unpack(buf[DEFAULT_UDP_HDR_SIZE:])
	if err != nil {
		t.logger.Error("Error unpacking DNS request", "err", err, "dnsReq", dnsReq)
		return
	}
	t.logger.Debug("received DNS request:", "dnsReq", dnsReq, "DNSNAME", dnsReq.Question[0].Name)

	var dnsResp *dns.Msg

	v6 := dnsReq.Question[0].Qtype == dns.TypeAAAA
	if !(v6) {
		// Check if we have a cached result for this query.
		// TODO: add periodic garbage collection of the cache.
		t.dnsClient.mu.RLock()
		if entry, ok := t.dnsClient.cache[dnsReq.Question[0].String()]; ok {
			// TODO: respect the TTL.
			if time.Since(entry.created) < time.Second*DNS_CACHE_TIMEOUT_SECONDS {
				t.logger.Debug("Using cached DNS result", "Question", dnsReq.Question[0].String())
				dnsResp = entry.result.Copy()
				dnsResp.Id = dnsReq.Id
			} else {
				t.logger.Debug("Cached DNS result expired", "Question", dnsReq.Question[0].String())
			}
		}
		t.dnsClient.mu.RUnlock()

		if dnsResp == nil {
			dnsHttpReq, err := dnsReq.Pack()
			if err != nil {
				t.logger.Error("Error packing DNS request", "err", err, "dnsResp", dnsResp)
				return
			}

			u := &url.URL{
				Scheme: "https",
				Host:   t.activeDoHServers[sport%uint16(len(t.activeDoHServers))], // randomly choose between the servers.
				Path:   "/dns-query",
			}
			if u.Port() == "443" {
				u.Host = u.Hostname()
			}

			req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(dnsHttpReq))
			if err != nil {
				t.logger.Error("Error creating DNS request", "err", err, "u", u)
				return
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Host = u.Host

			resp, err := t.dnsClient.h2Transport.RoundTrip(req)
			if err != nil {
				t.logger.Error("Error sending DNS request", "err", err, "req", req)
				return
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.logger.Error("Error closing body", "err", err)
				}
			}()
			if resp.StatusCode != http.StatusOK {
				t.logger.Error("Error sending DNS request", "resp.Status", resp.Status, "resp", resp)
				return
			}

			respBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.logger.Error("Error reading DNS response", "err", err, "resp", resp)
				return
			}
			dnsResp = new(dns.Msg)
			if err := dnsResp.Unpack(respBytes); err != nil {
				t.logger.Error("Error unpacking DNS response", "err", err, "respBytes", respBytes)
				return
			}

			// Cache the result.
			t.dnsClient.mu.Lock()
			t.dnsClient.cache[dnsReq.Question[0].String()] = &dnsCacheEntry{
				result:  dnsResp,
				created: dnsStart,
			}

			t.dnsClient.mu.Unlock()
		}

		t.logger.Debug("DNS response", "dnsResp", dnsResp)
	} else {
		// Ignore AAAA.
		dnsResp = dnsReq.Copy()
		t.logger.Debug("Ignoring DNS AAAA", "dnsResp", dnsResp)
	}
	dnsData, err := dnsResp.Pack()
	if err != nil {
		t.logger.Error("failed to pack DNS response", "err", err, "dnsResp", dnsResp)
		return
	}

	if len(dnsData) > (TUN_MTU - DEFAULT_IP_HDR_SIZE - DEFAULT_UDP_HDR_SIZE) {
		t.logger.Error("DNS response too big", "len(dnsData)", len(dnsData), "dnsData", dnsData)
		return
	}

	// Inject the DNS response back to the reverse direction
	const totalHdrLen = DEFAULT_IP_HDR_SIZE + DEFAULT_UDP_HDR_SIZE
	var pktsize int = len(dnsData) + totalHdrLen
	p := make([]byte, pktsize)
	copy(p[:], preBakedUDP[:])
	copy(p[totalHdrLen:], dnsData)

	setIPHdr(p[:], dst, src, uint16(pktsize))
	setUDPHdr(p[DEFAULT_IP_HDR_SIZE:], dport, sport, uint16(len(dnsData)+DEFAULT_UDP_HDR_SIZE))
	setIPandL4Checksum(p[:pktsize], PROTO_UDP)

	if err := t.pseudoSendToLinux(p[:pktsize]); err != nil {
		t.logger.Error("Error in pseudoSendToLinux", "err", err)
	}
}
