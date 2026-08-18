# SATP Demo Operations and TLS Findings

This document records the SATP demo environment tested on Datsun, the observed
network behavior, and the proposed direction for a TLS-enabled fourth case. It
supplements the README in each demo case and does not replace upstream setup
instructions.

## Environment

- Host: Datsun (`10.10.20.199`)
- Repository: `/opt/hyperledger-cacti/cacti-demos`
- Tested branch: `main`
- Tested baseline commit: `cf9976bf91eb86d7e8db66df35ae41bdabac65eb`
- Demo tested: `demos/satp/case_1`
- Container image: `tomassilva2187/satp-gateway:2026-02-02-1458`

Case 1 was successfully run using two local Hardhat EVM ledgers and two SATP
gateway containers. A 100-token transfer completed with the source balance at
0, destination balance at 100, and both bridge balances at 0.

## Network Map

- `172.18.0.1`: Datsun's Docker bridge gateway. It routes container traffic to
  host services, including the Hardhat ledgers on ports 8545 and 8546.
- `172.18.0.2`: SATP Gateway 1, connected to the source ledger on port 8545.
- `172.18.0.3`: SATP Gateway 2, connected to the destination ledger on port
  8546.
- The `.2` and `.3` gateways communicate with each other to coordinate the
  cross-ledger token transfer.
- The `.2 <-> .3` gateway traffic is unencrypted HTTP, using
  gRPC-Web/Protobuf over TCP port 3010.

## Packet Capture Evidence

The successful Case 1 run was captured with `tcpdump` and inspected in
Wireshark.

- Datsun evidence directory:
  `/opt/hyperledger-cacti/run-evidence/satp-case-1-pcap-20260818_081458`
- Capture file:
  `/opt/hyperledger-cacti/run-evidence/satp-case-1-pcap-20260818_081458/satp-case-1-traffic.pcap`
- Capture size: 1,093,205 bytes
- Packets: 1,309
- Capture duration: 44.718101 seconds
- SHA-256:
  `df53478b6dd846a4dc448ba84c3a10c9659d3ed28dc15288bf519652e19cb61f`
- SATP session:
  `e11d30d5-bf66-47e1-9b97-3cf26c2274fe-mockContext`
- Final status: `DONE` / `COMPLETED`

Wireshark can read gateway requests such as the following directly from the
capture, confirming that the transport is not encrypted:

- `/stage-0/cacti.satp.v02.service.SatpStage0Service/NewSession`
- `/stage-0/cacti.satp.v02.service.SatpStage0Service/PreSATPTransfer`

## TLS Configuration

### Question: Is there a TLS configuration file for Hyperledger Cacti?

For the SATP Case 1 demo, there is no dedicated TLS configuration file.

The gateway configuration files are:

- `config/gateway-1-config.json`
- `config/gateway-2-config.json`

Both explicitly use `http://`, not `https://`. They contain SECP256K1
public/private keys for signing SATP messages, but no TLS certificates, CA
trust, or TLS key configuration. TLS is therefore not currently configured
between the two gateways.

### Question: Are there other demo cases?

Yes. There are three SATP demo cases:

- Case 1 transfers a fungible ERC-20-like token between two EVM blockchains.
- Case 2 transfers a non-fungible ERC-721-like token between two EVM
  blockchains.
- Case 3 transfers fungible tokens among three EVM blockchains using the same
  pair of gateways.

Each case has its own `docker-compose.yaml`, README, and two gateway
configuration files.

### Question: Are any of those using TLS?

No. None of the three SATP demo cases use TLS.

All gateway-to-gateway and gateway-to-ledger endpoints use plain `http://`.
There are no TLS certificates, CA files, or TLS/SSL settings in their gateway
configurations or Compose files. The demos use cryptographic keys to sign SATP
messages, but message signing is separate from TLS transport encryption.

## Proposed Case 4

### Question: Is there a way to create Case 4 that uses TLS?

Yes. The cleanest Case 4 would clone Case 1 and add TLS without changing Cacti
code:

1. Keep the two Cacti gateway containers.
2. Add an Nginx or HAProxy TLS sidecar in front of each gateway.
3. Create a private demo CA and certificates for both gateways.
4. Change gateway addresses from `http://...` to `https://...`.
5. Give the gateway containers the CA certificate through
   `NODE_EXTRA_CA_CERTS`.
6. Verify that a new packet capture shows TLS between gateways instead of
   readable HTTP/Protobuf.

Mutual TLS is recommended so both gateways authenticate each other. The
current gateway image does not expose an obvious native TLS configuration, so
the reverse-proxy approach is the least invasive and easiest to demonstrate.

Private keys and other secrets must remain outside Git. Public demo CA and
certificate handling should be documented when Case 4 is implemented.
