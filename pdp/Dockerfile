FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/noiseutil ./common/noiseutil
COPY common/protocol ./common/protocol
COPY common/logutil ./common/logutil
COPY pdp ./pdp

RUN cat > go.work <<'WORK'
go 1.23

use (
	./pdp
	./common/noiseutil
	./common/protocol
	./common/logutil
)
WORK

WORKDIR /src/pdp
RUN go mod download
RUN go build -o pdp .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /src/pdp/pdp /app/pdp
COPY pdp/identity.json /app/identity.json
CMD ["/app/pdp"]
