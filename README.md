# PseudoTCP: A lightweight partial TCP stack for packet to stream interposition in Go

## What is PseudoTCP?

Many modern tunneling protocols, including IETF MASQUE, operate at a higher level of abstraction, dealing with flows rather than individual packets. However, this mismatch between the Android VPN interface and flow-based protocols poses a significant challenge for deploying MASQUE on Android devices.

We are building this interposition stack we call PseudoTCP, which enables the use of unmodified applications and unmodified Android devices with a MASQUE-enabled Android VPN that uses PseudoTCP to transparently handle translation between packets and flows as needed. This will make it possible for ordinary users to use a MASQUE-based Android VPN application as they would any other VPN or circumvention tool, yet the traffic will be tunneled using our MASQUE stack as HTTPS traffic via the MASQUE-enabled infrastructure in use for that service.

This will eventually integrate with our INVISV **masque** stack, which is an implementation of the [IETF MASQUE](https://datatracker.ietf.org/wg/masque/about/) tunneling protocol, written in Go. INVISV **masque** provides the client-side functionality needed for running a [Multi-Party Relay](https://invisv.com/articles/relay.html) service to protect users' network privacy.

**masque** enables application code on the client to tunnel bytestream (TCP) and packet (UDP) traffic via a MASQUE-supporting proxy, such as the [MASQUE service operated by Fastly](https://www.fastly.com/blog/kicking-off-privacy-week-fastly).

## How do I use PseudoTCP?

PseudoTCP is intended to be used as part of an android VPN app. We have a [sample Android VPN app](https://github.com/Invisv-Privacy/pseudotcp-example-app) that uses this stack that can be referenced.

We also have an [example binary](./example/tun/README.md) that you can use in order to bind the pseudotcp stack to a TUN interface for some amount of demonstration/evaluation.

## Testing
We currently have [integration tests](./tests/integration). They spin up a dockerized h2o proxy and leverage [gvisor's tcpip netstack](https://github.com/google/gvisor/tree/1a9abee80b7cb8655db7ba5714f0d3a8c00ccc67/pkg/tcpip) to emulate the android VPN host.

To run the integration tests:
```
$ go test -v ./...
```

## Benchmarking
We include a benchmark that evaluates the performance of a TCP connection over our stack with a HTTP GET request of various sizes. We can then compare those figures to a matching HTTP GET request directly from client to httptest.

```
$ go test -bench=. -run='^#' -benchtime=20x ./tests/integration > bench-results.txt 
$ benchstat ./bench-results.txt
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

It's important to note that "with pseudotcp" vs "without pseudotcp" is an extremely unfavorable comparison as "with pseudotcp" includes the overhead of not only our pseudotcp stack, but also the MASQUE connection overhead as well as the h2o proxy container and associated docker networking traversal.
