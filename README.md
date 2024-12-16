# PseudoTCP: A lightweight partial TCP stack for packet to stream interposition stack in Go

## What is PseudoTCP?

Many modern tunneling protocols, including IETF MASQUE, operate at a higher level of abstraction, dealing with flows rather than individual packets. However, this mismatch between the Android VPN interface and flow-based protocols poses a significant challenge for deploying MASQUE on Android devices.

We are building this interposition stack we call PseudoTCP, which enables the use of unmodified applications and unmodified Android devices with a MASQUE-enabled Android VPN that uses PseudoTCP to transparently handle translation between packets and flows as needed. This will make it possible for ordinary users to use a MASQUE-based Android VPN application as they would any other VPN or circumvention tool, yet the traffic will be tunneled using our MASQUE stack as HTTPS traffic via the MASQUE-enabled infrastructure in use for that service.

This will eventually integrate with our INVISV **masque** stack, which is an implementation of the [IETF MASQUE](https://datatracker.ietf.org/wg/masque/about/) tunneling protocol, written in Go. INVISV **masque** provides the client-side functionality needed for running a [Multi-Party Relay](https://invisv.com/articles/relay.html) service to protect users' network privacy.

**masque** enables application code on the client to tunnel bytestream (TCP) and packet (UDP) traffic via a MASQUE-supporting proxy, such as the [MASQUE service operated by Fastly](https://www.fastly.com/blog/kicking-off-privacy-week-fastly).

## How do I use PseudoTCP?

PseudoTCP is intended to be used as part of an android VPN app. We have a [sample Android VPN app](https://github.com/Invisv-Privacy/pseudotcp-example-app) that uses this stack that can be referenced.

We also have an [example binary](./example/tun/README.md) that you can use in order to bind the pseudotcp stack to a TUN interface for some amount of demonstration/evaluation.
