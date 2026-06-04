FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o client .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/client /app/client
CMD ["sleep", "infinity"]
