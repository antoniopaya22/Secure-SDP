# syntax=docker/dockerfile:1
# One build, three runtime images (select with --target / compose `target:`):
#   controller : sdp-controller (root or bridge role) + PKI tooling
#   gateway    : sdp-services (accepting host) + fwknop-server, iptables, Lynis
#   client     : sdp-client (initiating host) + fwknop-client, curl

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/antoniopaya22/Secure-SDP/internal/cli.Version=${VERSION}" \
      -o /out/ ./cmd/...

FROM debian:bookworm-slim AS controller
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin sdp
COPY --from=build /out/sdp-controller /usr/local/bin/
COPY lab/pki-bootstrap.sh /usr/local/bin/pki-bootstrap.sh
USER 10001
ENTRYPOINT ["sdp-controller"]
CMD ["serve", "--config", "/etc/sdp/controller.yml"]

FROM debian:bookworm-slim AS gateway
# Debian 12 packages of fwknop (2.6.10) and Lynis. The AH needs root:
# it owns the firewall and runs fwknopd (libpcap).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates fwknop-server iptables iproute2 conntrack lynis procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sdp-services /usr/local/bin/
ENTRYPOINT ["sdp-services"]
CMD ["serve", "--config", "/etc/sdp/services.yml"]

FROM debian:bookworm-slim AS client
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates fwknop-client curl iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/sdp --shell /bin/bash sdp
COPY --from=build /out/sdp-client /usr/local/bin/
USER 10001
WORKDIR /home/sdp
ENV SDP_CLIENT_CONFIG=/etc/sdp/client.yml
CMD ["sleep", "infinity"]
