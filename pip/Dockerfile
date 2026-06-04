FROM golang:1.23-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY main.go ./
RUN go build -o pip .

FROM alpine:latest
RUN apk add --no-cache curl sqlite-libs sqlite
WORKDIR /app
COPY --from=build /app/pip /app/pip
COPY clients.json /app/clients.json
VOLUME ["/data"]
CMD ["/app/pip"]
