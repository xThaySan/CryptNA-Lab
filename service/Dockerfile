FROM nginx:alpine
RUN apk add --no-cache iproute2
CMD ["/bin/sh", "-c", "ip route replace 10.200.0.0/24 via 172.22.0.40 && nginx -g 'daemon off;'"]
