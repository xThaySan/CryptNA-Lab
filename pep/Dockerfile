FROM golang:1.23-alpine AS build
WORKDIR /src

COPY common/cryptoutil ./common/cryptoutil
COPY common/protocol ./common/protocol
COPY common/logutil ./common/logutil
COPY pep ./pep

RUN cat > go.work <<'WORK'
go 1.23

use (
	./pep
	./common/cryptoutil
	./common/protocol
)
WORK

WORKDIR /src/pep
RUN go mod download
RUN go build -o pep .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /src/pep/pep /app/pep
CMD ["/app/pep"]
