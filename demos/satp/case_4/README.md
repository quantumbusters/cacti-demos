# SATP Case 4: TLS and Post-Quantum TLS

Case 4 preserves the Case 1 token transfer and routes the gateway-to-gateway
gRPC-Web/Protobuf channel through two NGINX peers. Each gateway uses local HTTP
to its colocated proxy. The proxies use TLS 1.3 with controlled authentication
and key-establishment profiles.

## Protected topology

    Gateway 1 -> HTTP proxy-1:8080 -> TLS proxy-2:3443 -> HTTP Gateway 2:3010
    Gateway 2 -> HTTP proxy-2:8080 -> TLS proxy-1:3443 -> HTTP Gateway 1:3010

Ledger RPC on ports 8545/8546 and OpenAPI control traffic on 4010/4110 are
outside the protected link. SATP message signing remains unchanged.

## Scenarios

| Scenario | TLS group | Certificate authentication |
| --- | --- | --- |
| 4A | X25519 | Classical server authentication |
| 4B | X25519 | Classical mutual TLS |
| 4C | X25519MLKEM768 | Classical mutual TLS |
| 4C-S | MLKEM768 | Classical mutual TLS |
| 4D | X25519MLKEM768 | ML-DSA-44 mutual TLS |

The proxy image is identical for all scenarios. Only the mounted scenario and
PKI profiles change. Case 4C-S deliberately removes X25519 from key
establishment so standalone MLKEM768 can be compared with hybrid Case 4C.

## Runtime

The proxy build pins:

- Debian 13 slim amd64 manifest
  sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f
- NGINX 1.26.3-3+deb13u7
- OpenSSL/libssl 3.5.7-1~deb13u2
- Verified proxy image ID
  sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c

DEB_REPO_URL must expose the pinned Debian package closure. Datsun defaults to
the HCDC infra-repo URL in the runner. The Dockerfile removes public Debian APT
sources before installation. The runner checks the local image ID against
the verified value; CASE4_EXPECTED_PROXY_DIGEST provides an explicit override
when intentionally validating a newly reviewed image.

The verified image archive is cached on infra-repo at:

    /srv/repo/docker/images/hcdc/cacti-satp-tls-proxy/nginx-1.26.3-openssl-3.5.7/amd64/cacti-satp-tls-proxy-nginx-1.26.3-openssl-3.5.7-amd64.docker.tar.gz

Its archive SHA-256 is
69f8516a3753c371c97ed7a9973deed51607d07b5a8a5876191211a901e59f92.

Generated PKI is written outside Git to
/opt/hyperledger-cacti/runtime/satp-case-4. Evidence is written to
/opt/hyperledger-cacti/run-evidence/satp-case-4.

## Run

Run as the ots account from the repository root:

    export PATH=/opt/hyperledger-cacti/bin:$PATH
    export CASE4_DEB_REPO_URL=http://10.10.20.155/nginx/linux/debian/trixie/amd64/nginx-debs

    make run-satp-case-4a
    make run-satp-case-4b
    make run-satp-case-4c
    make run-satp-case-4c-s
    make run-satp-case-4d

The first relevant run builds the proxy image and generates the required PKI
profile. Set CASE4_BUILD=0 to reuse the already-built image. The runner:

1. validates Compose and starts two Hardhat ledgers;
2. captures only proxy TLS port 3443 with TShark;
3. starts the two gateways and proxies;
4. repeats the Case 1 deployment and SATP transfer;
5. asserts status, balances, exact TLS group, authentication, and absence of
   cleartext SATP markers on the protected capture;
6. records versions, public certificates, logs, PCAP, extracted fields, and
   SHA-256 values;
7. removes only Case 4 containers/network and Hardhat ledger processes.

Run the fail-closed tests after their corresponding positive scenario:

    make verify-satp-case-4b-negative
    make verify-satp-case-4d-negative

They require rejection of a missing client certificate, untrusted client CA,
wrong server SAN, and invalid TLS group.

## Verified standalone ML-KEM result

Case 4C-S completed successfully on 2026-08-28. Both proxy directions negotiated
standalone MLKEM768 as TLS group 0x0201 (decimal 513) with classical mutual TLS.
The ServerHello key share was 1088 bytes. The SATP session completed with source
balance 0, destination balance 100, and both bridge balances 0. The capture
contained no decoded HTTP frames or readable SATP stage markers. Evidence is at:

    /opt/hyperledger-cacti/run-evidence/satp-case-4/4c-s/20260828_110840

## Controlled comparison

Run the three-repetition, five-scenario comparison as ots:

    make measure-satp-case-4

The comparison uses three deterministic rotating scenario orders. Each run
captures port 3443 once on the experiment Docker bridge, records the wall-clock
duration of satp-transact.py, and writes measurements.json plus measurements.csv
inside the run evidence directory. The comparison directory contains
run-index.tsv, runs.csv, summary.csv, summary.json, logs, and SHA256SUMS.

The verified 2026-08-28 comparison completed 15 of 15 runs:

    /opt/hyperledger-cacti/run-evidence/satp-case-4/comparisons/comparison-20260828-3x5

| Scenario | SATP ms, mean | ServerHello response ms, mean | Observable hello bytes | Wire bytes per TCP stream | Public CA/server/client DER bytes |
| --- | ---: | ---: | ---: | ---: | --- |
| 4A | 1690.9 | 0.683 | 375 | 6660.8 | 441 / 498.5 / 455.5 |
| 4B | 1680.3 | 0.701 | 375 | 7255.3 | 441 / 498.5 / 455.5 |
| 4C | 1721.4 | 0.854 | 2639 | 9497.1 | 441 / 498.5 / 455.5 |
| 4C-S | 1623.7 | 0.731 | 2575 | 9306.4 | 441 / 498.5 / 455.5 |
| 4D | 1614.7 | 0.779 | 2639 | 21718.7 | 4033 / 4093 / 4049 |

All runs completed the SATP transfer with the expected group and balances.
There were no interoperability failures, TCP retransmissions, or Hello Retry
Requests. Three repetitions are useful for this controlled demonstration but
are not a production benchmark. The SATP-duration distributions overlap, so
the observed means do not establish a meaningful latency improvement or
penalty.

TLS 1.3 encrypts Certificate and CertificateVerify. Without a TLS session-key
log, their on-wire sizes cannot be separated from other encrypted handshake
records. The results report this as unavailable rather than estimating it and
include DER sizes of the public certificate artifacts as a reproducible
comparison. ServerHello response time is ServerHello minus ClientHello on the
same TCP stream; it is not full handshake-completion latency.

## Security boundaries

Private demo keys stay under the external runtime root with mode 0600.
Generated certificates, keys, PCAPs, logs, and result bundles are ignored by
Git. These demo identities must never be reused for real assets or services.
The local gateway-to-proxy and proxy-to-gateway hops remain plaintext inside
the isolated Compose network; only the proxy-to-proxy link is claimed as
protected.
