FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/cryptoutil ./common/cryptoutil
COPY common/ipsecutil ./common/ipsecutil
COPY common/protocol ./common/protocol
COPY common/attest ./common/attest
COPY common/logutil ./common/logutil
COPY common/nattutil ./common/nattutil
COPY pep ./pep

RUN cat > go.work <<'WORK'
go 1.23

use (
	./pep
	./common/cryptoutil
	./common/ipsecutil
	./common/protocol
	./common/attest
	./common/logutil
	./common/nattutil
)
WORK

WORKDIR /src/pep
RUN go mod download
RUN go build -o pep .

FROM alpine:latest
ARG INSTALL_BPFTRACE=0
RUN apk add --no-cache curl iproute2 tcpdump iptables \
    && if [ "$INSTALL_BPFTRACE" = "1" ]; then apk add --no-cache bpftrace; fi
WORKDIR /app
COPY --from=build /src/pep/pep /app/pep
COPY pep/ebpf /app/ebpf
COPY pep/identity.json /app/pep_attestation_key.json
CMD ["/app/pep"]
