FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/cryptoutil ./common/cryptoutil
COPY common/noiseutil ./common/noiseutil
COPY common/protocol ./common/protocol
COPY tools/spa-send ./tools/spa-send

RUN cat > go.work <<'WORK'
go 1.23

use (
	./tools/spa-send
	./common/cryptoutil
	./common/noiseutil
	./common/protocol
)
WORK

WORKDIR /src/tools/spa-send
RUN go mod download
RUN go build -o spa-send .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /src/tools/spa-send/spa-send /app/spa-send
COPY client/config.json /app/config.json
COPY client/identity.json /app/identity.json
CMD ["sleep", "infinity"]
