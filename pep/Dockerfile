FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -o pep .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/pep /app/pep
CMD ["/app/pep"]
