ARG BASE_IMAGE=cacti-satp-tls-proxy:nginx-1.26.3-openssl-3.5.7@sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c
FROM ${BASE_IMAGE}

RUN install -d -o www-data -g www-data -m 0700 /run/case4/keylog \
 && sed -i '1i env SSLKEYLOGFILE;' /etc/nginx/nginx.conf
COPY --chmod=0555 libsslkeylog.so /opt/case4-keylog/libsslkeylog.so

LABEL org.opencontainers.image.title="Cacti SATP Case 4 analysis-only keylog proxy" \
      org.opencontainers.image.base.digest="sha256:47991a74bf4dfc31f38c226a4f523aaf95524eb719e051582aca6b098c5d3a5c" \
      org.opencontainers.image.security.warning="Exports TLS session secrets; analysis use only"
