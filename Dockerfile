FROM golang:1.22-bookworm AS builder

WORKDIR /work

COPY . ./

RUN go mod tidy && make

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables=1.8.* \
      ca-certificates=2023* \
      wireguard=1.0.* \
      iproute2=6.1.* \
      iputils-ping=3:20* \
      procps=2:4.* \
      iperf3=3.* \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /work/wireguard-go-vsock /usr/local/bin
