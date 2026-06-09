FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/cryptoutil ./common/cryptoutil
COPY common/ipsecutil ./common/ipsecutil
COPY common/noiseutil ./common/noiseutil
COPY common/protocol ./common/protocol
COPY common/logutil ./common/logutil
COPY common/nattutil ./common/nattutil
COPY tools/natt-listener ./tools/natt-listener
COPY client ./client

RUN cat > go.work <<'WORK'
go 1.23

use (
	./client
	./common/cryptoutil
	./common/ipsecutil
	./common/noiseutil
	./common/protocol
	./common/logutil
	./common/nattutil
	./tools/natt-listener
)
WORK

WORKDIR /src/client
RUN go mod download
RUN go build -o client .

WORKDIR /src/tools/natt-listener
RUN go mod download
RUN go build -o natt-listener .

FROM alpine:latest
RUN apk add --no-cache curl iproute2 tcpdump
WORKDIR /app
COPY --from=build /src/client/client /app/client
COPY --from=build /src/tools/natt-listener/natt-listener /app/natt-listener

CMD ["sh", "-c", "/app/natt-listener -port 4500 & sleep infinity"]