FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o pdp .

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/pdp /app/pdp
CMD ["/app/pdp"]
