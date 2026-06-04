FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -o client .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/client /app/client
COPY config.json /app/config.json
COPY identity.json /app/identity.json
CMD ["sleep", "infinity"]
