# PseudoTCP

[![Lint and Test](https://github.com/invisv-privacy/pseudotcp/actions/workflows/build.yaml/badge.svg)](https://github.com/Invisv-Privacy/pseudotcp/actions/workflows/build.yaml)
[![GoDoc](https://pkg.go.dev/badge/github.com/invisv-privacy/pseudotcp?status.svg)](https://pkg.go.dev/github.com/invisv-privacy/pseudotcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/invisv-privacy/pseudotcp)](https://goreportcard.com/report/github.com/invisv-privacy/pseudotcp)

A lightweight partial TCP stack for packet to stream interposition in Go

## 📖 What is PseudoTCP?

Many modern tunneling protocols, including IETF MASQUE, operate at a higher level of abstraction, dealing with flows rather than individual packets. However, this mismatch between the Android VPN interface and flow-based protocols poses a significant challenge for deploying MASQUE on Android devices.

PseudoTCP is an interposition stack that enables the use of unmodified applications and unmodified Android devices with a MASQUE-enabled Android VPN. It transparently handles translation between packets and flows as needed, making it possible for ordinary users to use a MASQUE-based Android VPN application as they would any other VPN or circumvention tool. The traffic is tunneled using our MASQUE stack as HTTPS traffic via the MASQUE-enabled infrastructure.

This project integrates with our INVISV **masque** stack, which is an implementation of the [IETF MASQUE](https://datatracker.ietf.org/wg/masque/about/) tunneling protocol, written in Go. INVISV **masque** provides the client-side functionality needed for running a [Multi-Party Relay](https://invisv.com/articles/relay.html) service to protect users' network privacy.

**masque** enables application code on the client to tunnel bytestream (TCP) and packet (UDP) traffic via a MASQUE-supporting proxy, such as the [MASQUE service operated by Fastly](https://www.fastly.com/blog/kicking-off-privacy-week-fastly).

## 🚀 Getting Started

### Prerequisites

- Go 1.23 or higher
- Docker (for running integration tests)

## 🔧 Usage

PseudoTCP is intended to be used as part of an Android VPN app. We provide:

1. A [sample Android VPN app](https://github.com/Invisv-Privacy/pseudotcp-example-app) that demonstrates how to use this stack
2. An [example binary](./example/tun/README.md) that binds the pseudotcp stack to a TUN interface for demonstration and evaluation

## 🧪 Testing

We have comprehensive [integration tests](./tests/integration) that:
- Spin up a dockerized h2o proxy
- Leverage [gvisor's tcpip netstack](https://github.com/google/gvisor/tree/master/pkg/tcpip) to emulate the Android VPN host
- Assert that both [HTTPS GET requests](./tests/integration/https_get_test.go) as well as [UDP connections](./tests/integration/udp_test.go) are successful.

To run the integration tests:

```bash
$ go test -v ./tests/integration
```

### Linting

We use golangci-lint for code quality checks. See [the install instructions](https://golangci-lint.run/welcome/install/) for comprehensive directions for your platform.

```bash
# Run linting
$ golangci-lint run
```

## 📊 Benchmarking

We include [benchmarks](./tests/integration/benchmark_test.go) that evaluate the performance of TCP connections over our stack with HTTP GET requests of various sizes, comparing them to direct HTTP GET requests:

```bash
# Run benchmarks
$ go test -bench=. -run='^#' -benchtime=20x ./tests/integration > bench-results.txt

# Analyze results
$ benchstat ./bench-results.txt
```

Sample benchmark results:

```
goos: linux
goarch: amd64
pkg: github.com/invisv-privacy/pseudotcp/tests/integration
cpu: Intel(R) Core(TM) i7-8665U CPU @ 1.90GHz
                                                  │ ./bench.txt  │
                                                  │    sec/op    │
Throughput/with-pseudotcp-payload-10000B-8          602.7µ ± ∞ ¹
Throughput/without-pseudotcp-payload-10000B-8       199.0µ ± ∞ ¹
Throughput/with-pseudotcp-payload-100000B-8         1.022m ± ∞ ¹
Throughput/without-pseudotcp-payload-100000B-8      665.0µ ± ∞ ¹
Throughput/with-pseudotcp-payload-1000000B-8        5.817m ± ∞ ¹
Throughput/without-pseudotcp-payload-1000000B-8     5.080m ± ∞ ¹
Throughput/with-pseudotcp-payload-10000000B-8       45.71m ± ∞ ¹
Throughput/without-pseudotcp-payload-10000000B-8    36.35m ± ∞ ¹
Throughput/with-pseudotcp-payload-100000000B-8      934.4m ± ∞ ¹
Throughput/without-pseudotcp-payload-100000000B-8   368.4m ± ∞ ¹
geomean                                             8.202m
¹ need >= 6 samples for confidence interval at level 0.95
```

**Note:** "with pseudotcp" vs "without pseudotcp" is an unfavorable comparison as "with pseudotcp" includes the overhead of not only our pseudotcp stack, but also the MASQUE connection overhead as well as the h2o proxy container and associated docker networking traversal.

## 📄 License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](./LICENSE) file.
