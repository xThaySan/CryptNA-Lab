FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/cryptoutil ./common/cryptoutil
COPY common/noiseutil ./common/noiseutil
COPY common/protocol ./common/protocol
COPY common/logutil ./common/logutil
COPY client ./client

RUN cat > go.work <<'WORK'
go 1.23

use (
	./client
	./common/cryptoutil
	./common/noiseutil
	./common/protocol
)
WORK

WORKDIR /src/client
RUN go mod download
RUN go build -o client .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /src/client/client /app/client
COPY client/config.json /app/config.json
COPY client/identity.json /app/identity.json
CMD ["sleep", "infinity"]
