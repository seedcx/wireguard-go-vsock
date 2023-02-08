# Go Implementation of [WireGuard](https://www.wireguard.com/) over VSOCK

This is an implementation of WireGuard in Go with support to [`vsock`](https://man7.org/linux/man-pages/man7/vsock.7.html).

## Usage

Run:

```
$ wireguard-go-vsock wg0
```

This will create an interface and fork into the background. An ephemerous VSOCK port (`VMADDR_PORT_ANY`) will be bound to any VSOCK CID (`VMADDR_CID_ANY`).

To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run `wireguard-go-vsock` without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go-vsock -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

Note that this implementation will adopt addresses in the format `vsock://<cid>:<port>` where `cid` is the VSOCK address and `port` the port number. Note that due to certain implementation limitations at the base `wireguard-go`, the port should not be set as 32-bits, but 16-bits instead (as in Internet addresses).

By default, `wireguard-go-vsock` uses `SOCK_STREAM` socket type. If you want to use `SOCK_DGRAM`, just add `-d` to the command line. Just note that `SOCK_DGRAM` isn't supported by every hypervisor, if not supported, you should see `ENODEV` (no such device) at the logs. The `SOCK_STREAM` vsock implementation supports a single connection only, which is the most common use case when dealing with AWS Nitro Enclaves.

## Platforms

### Linux

This will run on Linux with support to `AF_VSOCK` only.

### Other OSes

There is no support yet.

## Building

This requires an installation of [go](https://golang.org) ≥ 1.19.

```
$ git clone https://github.com/balena/wireguard-go-vsock
$ cd wireguard-go-vsock
$ make
```

## License

    Copyright (C) 2017-2022 WireGuard LLC.
    Copyright (C) 2023 Guilherme Versiani.
    
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
