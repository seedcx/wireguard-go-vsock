package vsockconn

import (
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

var (
	_ conn.Endpoint = (*SockaddrInet4Endpoint)(nil)
)

type SockaddrInet4Endpoint struct {
	mu  sync.Mutex
	dst [unsafe.Sizeof(unix.SockaddrInet4{})]byte
	src [unsafe.Sizeof(unix.SockaddrInet4{})]byte
}

func (endpoint *SockaddrInet4Endpoint) Src4() *unix.SockaddrInet4 { return endpoint.src4() }
func (endpoint *SockaddrInet4Endpoint) Dst4() *unix.SockaddrInet4 { return endpoint.dst4() }

func (endpoint *SockaddrInet4Endpoint) src4() *unix.SockaddrInet4 {
	return (*unix.SockaddrInet4)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *SockaddrInet4Endpoint) dst4() *unix.SockaddrInet4 {
	return (*unix.SockaddrInet4)(unsafe.Pointer(&endpoint.dst[0]))
}

func (end *SockaddrInet4Endpoint) SrcIP() netip.Addr {
	return netip.AddrFrom4(end.src4().Addr)
}

func (end *SockaddrInet4Endpoint) DstIP() netip.Addr {
	return netip.AddrFrom4(end.dst4().Addr)
}

func (end *SockaddrInet4Endpoint) DstToBytes() []byte {
	return (*[unsafe.Offsetof(end.dst4().Addr) + unsafe.Sizeof(end.dst4().Addr)]byte)(unsafe.Pointer(end.dst4()))[:]
}

func (end *SockaddrInet4Endpoint) SrcToString() string {
	return end.SrcIP().String()
}

func (end *SockaddrInet4Endpoint) DstToString() string {
	var port int
	port = end.dst4().Port
	return netip.AddrPortFrom(end.DstIP(), uint16(port)).String()
}

func (end *SockaddrInet4Endpoint) ClearDst() {
	for i := range end.dst {
		end.dst[i] = 0
	}
}

func (end *SockaddrInet4Endpoint) ClearSrc() {
	for i := range end.src {
		end.src[i] = 0
	}
}
