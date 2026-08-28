ARG DEBIAN_BASE=docker.io/library/debian:13-slim@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f
FROM ${DEBIAN_BASE}

ARG DEB_REPO_URL
ARG NGINX_VERSION=1.26.3-3+deb13u7
ARG OPENSSL_VERSION=3.5.7-1~deb13u2

RUN test -n "${DEB_REPO_URL}" \
 && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && printf '%s\n' "deb [trusted=yes] ${DEB_REPO_URL} ./" >/etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      "nginx=${NGINX_VERSION}" "nginx-common=${NGINX_VERSION}" \
      "libssl3t64=${OPENSSL_VERSION}" "openssl=${OPENSSL_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf

LABEL org.opencontainers.image.title="Cacti SATP Case 4 TLS proxy" \
      org.opencontainers.image.base.digest="sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f" \
      org.opencontainers.image.nginx.version="1.26.3-3+deb13u7" \
      org.opencontainers.image.openssl.version="3.5.7-1~deb13u2"

EXPOSE 8080 3443
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD nginx -t || exit 1
CMD ["nginx", "-g", "daemon off;"]
