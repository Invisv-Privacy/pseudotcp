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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSGet(t *testing.T) {
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

		tcpConn, err := gonet.DialTCPWithBind(context.Background(), netstack, tcpip.FullAddress{
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
