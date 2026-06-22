FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/protocol ./common/protocol
COPY common/attest ./common/attest
COPY verifier ./verifier

RUN cat > go.work <<'WORK'
go 1.23

use (
	./verifier
	./common/protocol
	./common/attest
)
WORK

WORKDIR /src/verifier
RUN go mod download
RUN go build -o verifier .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /src/verifier/verifier /app/verifier
COPY verifier/identity.json /app/identity.json
CMD ["/app/verifier"]
