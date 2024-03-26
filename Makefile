PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: wireguard-go-vsock

wireguard-go-vsock: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go-vsock
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go-vsock"

test:
	go test -timeout 60s -coverprofile coverage.out ./...

integration-test:
	docker run -v ${PWD}:/work -w /work --privileged -ti --rm golang:1.22 \
	 	bash -c 'apt-get update && \
						 apt-get install -y --no-install-recommends net-tools iproute2 iputils-ping && \
						 go test -v -tags integration -timeout 60s -coverprofile integration_coverage.out ./...'

clean:
	rm -f wireguard-go-vsock

.PHONY: all clean test install
