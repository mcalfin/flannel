FROM golang:1.23 AS builder
WORKDIR /workspace
COPY . .
RUN make dist/flanneld

FROM alpine:3.17
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.edge.kernel.org/' /etc/apk/repositories && \
    apk update && apk add --no-cache iptables ip6tables
COPY --from=builder /workspace/dist/flanneld /usr/local/bin/flanneld
ENTRYPOINT ["/usr/local/bin/flanneld"]

