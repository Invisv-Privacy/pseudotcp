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

type DNSResponse struct {
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"ttl"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// The default DNS-over-HTTPS server to use for DNS queries.
var DEFAULT_DOH_SERVER_ADDRS = []string{"1.1.1.1:443", "1.0.0.1:443", "1.1.1.2:443", "1.0.0.2:443"}
var DEFAULT_POPULAR_DNS_NAMES []string = []string{"api.invisv.com"}

// configuredDoHServers is the list of servers we were configured to use.
// This list is copied to activeDoHServers when the relay is started.
// If this is empty, we use the default list.
var configuredDoHServers []string

// activeDoHServers is the list of servers currently in use.
var activeDoHServers []string

func ResolveDOHJSON(host string) (string, error) {
	var d net.Dialer
	d.Control = dialerControlProtect(currentProtect)

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
		logger.Error("Error creating DNS request", "err", err, "host", host)
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	response, err := tr.RoundTrip(req)
	if err != nil {
		logger.Error("Error sending DNS request", "err", err, "req", req)
		return "", err
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			logger.Error("Error closing body", "err", err)
		}
	}()

	err = writer.Close()
	if err != nil {
		logger.Error("Error closing writer", "err", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		logger.Error("Error reading DNS response", "err", err, "response", response)
		return "", err
	}

	logger.Debug("DNS response", "body", string(body))
	dnsResponse := DNSResponse{}
	err = json.Unmarshal(body, &dnsResponse)
	if err != nil {
		logger.Error("Error unmarshalling DNS response", "err", err, "dnsresponse", dnsResponse)
		return "", err
	}
	logger.Debug("DNS response", "dnsResponse", dnsResponse)
	for _, answer := range dnsResponse.Answer {
		if answer.Type == 1 {
			logger.Debug("DNS response Type 1", "answer.Data", answer.Data)
			return answer.Data, nil
		}
	}
	return "", errors.New("no A record found")
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

var dnsClient *dnsClientState

// initDNSClient initializes the DNS client.
func initDnsClient() {
	dnsClient = &dnsClientState{
		h2Transport: &http2.Transport{AllowHTTP: false,
			DisableCompression: true,
		},
		cache: make(map[string]*dnsCacheEntry),
	}

	if len(configuredDoHServers) > 0 {
		activeDoHServers = make([]string, len(configuredDoHServers))
		copy(activeDoHServers, configuredDoHServers)
	} else {
		activeDoHServers = make([]string, len(DEFAULT_DOH_SERVER_ADDRS))
		copy(activeDoHServers, DEFAULT_DOH_SERVER_ADDRS)
	}

	go precachePopularDnsDomains()
}

func precachePopularDnsDomains() {
	for _, domain := range DEFAULT_POPULAR_DNS_NAMES {
		if _, err := net.LookupHost(domain); err != nil {
			logger.Error("Error looking up host", "err", err, "domain", domain)
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
func handleDNS(src uint32, sport uint16, dst uint32, dport uint16, buf []byte) {
	dnsStart := time.Now()

	dnsReq := new(dns.Msg)
	err := dnsReq.Unpack(buf[DEFAULT_UDP_HDR_SIZE:])
	if err != nil {
		logger.Error("Error unpacking DNS request", "err", err, "dnsReq", dnsReq)
		return
	}
	logger.Debug("received DNS request:", "dnsReq", dnsReq, "DNSNAME", dnsReq.Question[0].Name)

	var dnsResp *dns.Msg

	v6 := dnsReq.Question[0].Qtype == dns.TypeAAAA
	if !(v6) {
		// Check if we have a cached result for this query.
		// TODO: add periodic garbage collection of the cache.
		dnsClient.mu.RLock()
		if entry, ok := dnsClient.cache[dnsReq.Question[0].String()]; ok {
			// TODO: respect the TTL.
			if time.Since(entry.created) < time.Second*DNS_CACHE_TIMEOUT_SECONDS {
				logger.Debug("Using cached DNS result", "Question", dnsReq.Question[0].String())
				dnsResp = entry.result.Copy()
				dnsResp.Id = dnsReq.Id
			} else {
				logger.Debug("Cached DNS result expired", "Question", dnsReq.Question[0].String())
			}
		}
		dnsClient.mu.RUnlock()

		if dnsResp == nil {
			dnsHttpReq, err := dnsReq.Pack()
			if err != nil {
				logger.Error("Error packing DNS request", "err", err, "dnsResp", dnsResp)
				return
			}

			u := &url.URL{
				Scheme: "https",
				Host:   activeDoHServers[sport%uint16(len(activeDoHServers))], // randomly choose between the servers.
				Path:   "/dns-query",
			}
			if u.Port() == "443" {
				u.Host = u.Hostname()
			}

			req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(dnsHttpReq))
			if err != nil {
				logger.Error("Error creating DNS request", "err", err, "u", u)
				return
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Host = u.Host

			resp, err := dnsClient.h2Transport.RoundTrip(req)
			if err != nil {
				logger.Error("Error sending DNS request", "err", err, "req", req)
				return
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					logger.Error("Error closing body", "err", err)
				}
			}()
			if resp.StatusCode != http.StatusOK {
				logger.Error("Error sending DNS request", "resp.Status", resp.Status, "resp", resp)
				return
			}

			respBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Error("Error reading DNS response", "err", err, "resp", resp)
				return
			}
			dnsResp = new(dns.Msg)
			if err := dnsResp.Unpack(respBytes); err != nil {
				logger.Error("Error unpacking DNS response", "err", err, "respBytes", respBytes)
				return
			}

			// Cache the result.
			dnsClient.mu.Lock()
			dnsClient.cache[dnsReq.Question[0].String()] = &dnsCacheEntry{
				result:  dnsResp,
				created: dnsStart,
			}

			dnsClient.mu.Unlock()
		}

		logger.Debug("DNS response", "dnsResp", dnsResp)
	} else {
		// Ignore AAAA.
		dnsResp = dnsReq.Copy()
		logger.Debug("Ignoring DNS AAAA", "dnsResp", dnsResp)
	}
	dnsData, err := dnsResp.Pack()
	if err != nil {
		logger.Error("failed to pack DNS response", "err", err, "dnsResp", dnsResp)
		return
	}

	if len(dnsData) > (TUN_MTU - DEFAULT_IP_HDR_SIZE - DEFAULT_UDP_HDR_SIZE) {
		logger.Error("DNS response too big", "len(dnsData)", len(dnsData), "dnsData", dnsData)
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

	if err := pseudoSendToLinux(p[:pktsize]); err != nil {
		logger.Error("Error in pseudoSendToLinux", "err", err)
	}
}
