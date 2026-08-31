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

## Verified Case 4 Results  2026-08-28

Case 4 was implemented and tested on feature/satp-case-4-tls-pqc. The
implementation uses two instances of one Debian 13 NGINX 1.26.3 image running
with OpenSSL 3.5.7. Gateway-local hops remain HTTP; the proxy-to-proxy link is
TLS 1.3. No Cacti application source change was required.

All four scenarios completed the same 100-token transfer as Case 1 with source
balance 0, destination balance 100, and both bridge balances 0:

- 4A: X25519 with classical server authentication.
- 4B: X25519 with classical mutual TLS.
- 4C: X25519MLKEM768 with the same classical mutual-TLS identities as 4B.
- 4C-S: standalone MLKEM768 with the same classical mutual-TLS identities.
- 4D: X25519MLKEM768 with ML-DSA-44 CA, server, and client certificates.

The hybrid ServerHello key-share group was captured as wire value 4588
(0x11ec) with 1120 bytes of key-exchange data. NGINX 1.26 logs this new group
by wire ID; the scenario configuration and OpenSSL 3.5.7 identify it as
X25519MLKEM768.

Classical 4B and ML-DSA 4D negative suites rejected missing client
certificates, untrusted client CAs, wrong server SANs, and invalid TLS groups.
Each successful scenario has a PCAP, public certificates, runtime/version
manifest, protocol assertions, logs, results, cleanup checks, and SHA-256
index under /opt/hyperledger-cacti/run-evidence/satp-case-4.

Case 4C-S was verified on 2026-08-28 in evidence directory
/opt/hyperledger-cacti/run-evidence/satp-case-4/4c-s/20260828_110840.
NGINX logged group 0x0201 in both directions, TShark extracted group 513 and a
1088-byte ServerHello key share, mutual-TLS verification was SUCCESS, and no
classical or hybrid key-establishment fallback occurred.


## Verified Case 4 Comparison  2026-08-28

The controlled measurement set ran 4A, 4B, 4C, 4C-S, and 4D three times each
using deterministic rotating orders. All 15 transfers passed with the expected
TLS group, authentication, SATP status, and balances. TShark observed no TCP
retransmissions or Hello Retry Requests. The aggregate evidence is:

    /opt/hyperledger-cacti/run-evidence/satp-case-4/comparisons/comparison-20260828-3x5

The classical 4B mTLS baseline used 375 observable ClientHello plus ServerHello
bytes. Hybrid 4C used 2639 bytes and standalone 4C-S used 2575 bytes. Relative
to 4B, mean normalized wire bytes per observed TCP stream increased 30.9% for
4C and 28.3% for 4C-S. Case 4D used the same hybrid hello sizes as 4C, but its
ML-DSA-44 public certificate artifacts were about 4 KB each rather than about
0.5 KB, and its normalized wire bytes were about three times the 4B baseline.

Mean SATP durations ranged from 1614.7 to 1721.4 ms, with overlapping
within-scenario variability across only three repetitions. Treat these values
as demonstration measurements, not evidence that a PQC profile improves or
degrades end-to-end SATP latency.

TLS 1.3 encrypts Certificate and CertificateVerify, and this experiment did not
export TLS session keys. Their individual on-wire sizes are therefore recorded
as unavailable. The dataset supplies public-certificate DER sizes instead.
ServerHello response time measures ServerHello minus ClientHello on the same
stream and is not full handshake-completion latency. The source runner captures
only the experiment Docker bridge so retransmission and segmentation counts are
not inflated by duplicate Linux any-interface observations.


## Analysis-Only Wireshark Decryption Bundle  2026-08-31

NGINX 1.26.3 does not implement the ssl_key_log directive, and OpenSSL does not
honor SSLKEYLOGFILE unless its embedding application registers a callback. A
separate analysis-only image therefore layers a small versioned callback shim
on the unchanged verified proxy image. It preserves SSLKEYLOGFILE in NGINX
workers and writes NSS-format secrets only when the key-log Compose override is
explicitly enabled.

Fresh 4A, 4B, 4C, 4C-S, and 4D runs each completed successfully and produced a
paired proxy-tls.pcapng plus wireshark.keys. TShark reopened every copied pair
and decrypted nine HTTP requests: eight SATP stage calls and the reverse-path
probe. The bundle, index, instructions, and SHA-256 manifest are under:

    /opt/hyperledger-cacti/run-evidence/satp-case-4/decryptable/wireshark-20260831

The key-log image digest is
sha256:d7c5e34a5690225cd23c30e712bcfac57cebc0272bc5a4c4d81f6a6a74522b38.
Its infra-repo archive SHA-256 is
bc0f4a38c5c6e2c425a9ff06a299f8ed60b7d1ae3c5d6a13401c5924a84440ca.

The bundle root, scenario directories, captures, and key logs are readable by
Datsun users so project participants are not locked out of the evidence. Share
each capture together with its matching key log; the pair is intentionally
decryptable. Do not enable this instrumentation for production traffic.
Existing captures without key logs cannot be decrypted retroactively.
