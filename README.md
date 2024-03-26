# Go Implementation of [WireGuard](https://www.wireguard.com/) over VSOCK

This is an implementation of WireGuard in Go with support to [`vsock`](https://man7.org/linux/man-pages/man7/vsock.7.html).

## Quick Start

### At the Enclave

A new interface is added with:

    wireguard-go-vsock wg0

An IP address and peer can be assigned with `ifconfig(8)` or `ip-address(8)`:

    ip address add dev wg0 203.0.113.2 peer 203.0.113.1

The interface can be configured with keys and peer endpoints with the `wg(8)` utility:

    wg set wg0 \
      private-key /path/to/enclave-privkey \
      listen-port 51820 \
      peer xMjphMUyLIGExyJluSslD9tjaIcF9QS6ADyI8DOTzyg= \
      allowed-ips 0.0.0.0/0 \
      endpoint 0.0.0.2:8172

Notice that the above setting indicates that the peer endpoint is actually `host(2)` (context ID = 2). The `wg` command requires passing VSOCK CID as IPv4.

Finally, the interface can then be activated with `ifconfig(8)` or `ip-link(8)`:

    ip link set up dev wg0

### At the Host

A new interface is added with:

    wireguard-go-vsock wg0

An IP address and peer can be assigned with `ifconfig(8)` or `ip-address(8)`:

    ip address add dev wg0 203.0.113.1 peer 203.0.113.2

The interface can be configured with keys and peer endpoints with the `wg(8)` utility:

    wg set wg0 \
      private-key /path/to/host-privkey \
      listen-port 8172 \
      peer +SjU9sG4bBLyViwQsHxVXFxX/QD1npDI2NiHZyccv3w= \
      allowed-ips 0.0.0.0/0 \
      endpoint 0.0.0.6:51820

Notice that the above setting indicates that the peer endpoint is actually `vm(6)` (context ID = 6). The `wg` command requires passing VSOCK CID as IPv4.

Activate the interface with `ifconfig(8)` or `ip-link(8)`:

    ip link set up dev wg0

After setting both ends, at the host try to execute simple network commands such as:

    ping 203.0.113.2

## Usage

Run:

    wireguard-go-vsock wg0

This will create an interface and fork into the background. An ephemerous VSOCK port (`VMADDR_PORT_ANY`) will be bound to any VSOCK CID (`VMADDR_CID_ANY`).

To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run `wireguard-go-vsock` without forking to the background, pass `-f` or `--foreground`:

    wireguard-go-vsock -f wg0

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

Note that this implementation accepts addresses in the following format when wireguard UAP is used directly (`wg` command doesn't accept it!):

    vsock-address := vsock-address-cid ":" port
    vsock-address-cid := hypervisor-address | local-address | host-address | vm-address
    hypervisor-address := "hypervisor(0)"
    local-address := "local(1)"
    host-address := "host(2)"
    vm-address := "vm(" vm-contextID ")"
    vm-contextID := UINT32 ≥ 3
    port := UINT32

Note that due to underlying limitations at the base `wireguard-go`, the port should not be set as 32-bits, but 16-bits instead (as in Internet addresses).

## TCP support

In order to test out of AWS Nitro Enclaves, `wireguard-go-vsock` also supports the `tcp`, `tcp4` and `tcp6` network families (as int the `net` Go package). Just pass `-n/--network` parameter in the command line, like:

    wireguard-go-vsock -n tcp wg0

The above will initialize WireGuard under the network type `tcp`.

## Platforms

### Linux

In order to support VSOCK, this will run on Linux with support to `AF_VSOCK` only. It is possible to use `AF_STREAM` by using the `-n/--network` flag, for experimental purposes.

### Other OSes

There is no support to VSOCK yet. It is possible to use `AF_STREAM` by using the `-n/--network` flag, for experimental purposes as in Linux.

## Building

This requires an installation of [go](https://golang.org) ≥ 1.19.

    $ git clone https://github.com/seedcx/wireguard-go-vsock
    $ cd wireguard-go-vsock
    $ make

## License

    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
    Copyright (C) 2023-2024 Guilherme Versiani. All Rights Reserved.
    Copyright (C) 2024 Zero Hash Holdings Ltd. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
