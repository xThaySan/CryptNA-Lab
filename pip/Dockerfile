FROM golang:1.23-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src

COPY common/protocol ./common/protocol
COPY common/logutil ./common/logutil
COPY pip ./pip

RUN cat > go.work <<'WORK'
go 1.23

use (
	./pip
	./common/protocol
)
WORK

WORKDIR /src/pip
RUN go mod download
RUN go build -o pip .

FROM alpine:latest
RUN apk add --no-cache curl sqlite-libs sqlite
WORKDIR /app
COPY --from=build /src/pip/pip /app/pip
COPY pip/clients.json /app/clients.json
VOLUME ["/data"]
CMD ["/app/pip"]
