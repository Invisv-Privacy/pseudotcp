package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/invisv-privacy/pseudotcp"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

var sizes = []int{10000, 100000, 1000000, 10000000, 100000000}

func BenchmarkThroughput(b *testing.B) {
	// Disable debug logging (which is setup in TestMain)
	// because output is too verbose
	level := slog.LevelInfo
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Set verbose to false
	err := pseudotcp.Init(sendPacket, false, containerIP, "8444")
	require.NoError(b, err, "pseudotcp.Init")

	defer pseudotcp.Shutdown()

	// Start target HTTP/S server that replies with a payload determined by "?size" url query
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sizeString := r.URL.Query().Get("size")
		size, err := strconv.Atoi(sizeString)
		require.NoError(b, err, "strconv.Atoi")
		_, err = io.CopyN(w, rand.Reader, int64(size))
		require.NoError(b, err, "io.CopyN")
	}))

	// We want to listen on 0.0.0.0 because the proxy container will be on a different non-localhost network.
	// In order to do that we have this kind of awkward hack borrowed from:
	// https://stackoverflow.com/a/42218765/1787596
	l, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(b, err, "httptest server net.Listen")

	// Swap out the default test server listener with our custom one listening on 0.0.0.0
	require.NoError(b, ts.Listener.Close(), "ts.Listener.Close()")
	ts.Listener = l

	ts.Start()
	defer ts.Close()

	urlSplit := strings.Split(ts.URL, ":")
	port := urlSplit[len(urlSplit)-1]

	dockerHostURL := fmt.Sprintf("http://%v:%v", containerGateway, port)

	logger.Debug("Test server listening", "ts", ts, "dockerHostURL", dockerHostURL)

	dialWrapper := func(ctx context.Context, network, addr string) (net.Conn, error) {
		logger.Debug("dialing", "addr", addr)
		split := strings.Split(addr, ":")
		hostname := split[0]
		port, err := strconv.Atoi(split[1])
		require.NoError(b, err, "strconv.Atoi")

		ips, err := net.LookupIP(hostname)
		require.NoError(b, err, "LookupIP")
		require.NotEmpty(b, ips, "LookupIP not Empty")

		return gonet.DialTCPWithBind(context.Background(), netstack, tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFrom4(endpointIP.As4()),
		}, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(ips[0].To4()),
			Port: uint16(port),
		}, ipv4.ProtocolNumber)
	}

	transport := &http.Transport{
		DialContext: dialWrapper,
	}

	httpClient := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	defaultClient := http.Client{
		Timeout: 30 * time.Second,
	}

	// Test different payload sizes
	for _, size := range sizes {
		b.Run(fmt.Sprintf("with-pseudotcp-payload-%dB", size), func(b *testing.B) {
			url := fmt.Sprintf("%s?size=%d", dockerHostURL, size)
			for i := 0; i < b.N; i++ {
				req, err := http.NewRequest(http.MethodGet, url, nil)
				require.NoError(b, err, "NewRequest")

				res, err := httpClient.Do(req)
				require.NoError(b, err, "httpClient.Do")

				defer func() {
					err := res.Body.Close()
					require.NoError(b, err, "res.Body.Close()")
				}()

				_, err = io.ReadAll(res.Body)
				require.NoError(b, err, "io.ReadAll")
			}
		})

		b.Run(fmt.Sprintf("without-pseudotcp-payload-%dB", size), func(b *testing.B) {
			url := fmt.Sprintf("%s?size=%d", dockerHostURL, size)
			for i := 0; i < b.N; i++ {
				req, err := http.NewRequest(http.MethodGet, url, nil)
				require.NoError(b, err, "NewRequest")

				res, err := defaultClient.Do(req)
				require.NoError(b, err, "httpClient.Do")

				defer func() {
					err := res.Body.Close()
					require.NoError(b, err, "res.Body.Close()")
				}()

				_, err = io.ReadAll(res.Body)
				require.NoError(b, err, "io.ReadAll")
			}
		})
	}
}
