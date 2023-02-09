package vsockconn

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	AnyCID  = math.MaxUint32 // VMADDR_CID_ANY (-1U)
	AnyPort = math.MaxUint32 // VMADDR_PORT_ANY (-1U)
)

var (
	_ conn.Endpoint = (*VsockEndpoint)(nil)
)

type VsockEndpoint struct {
	mu  sync.Mutex
	dst [unsafe.Sizeof(unix.SockaddrVM{})]byte
	src [unsafe.Sizeof(unix.SockaddrVM{})]byte
}

func (endpoint *VsockEndpoint) Src() *unix.SockaddrVM {
	return (*unix.SockaddrVM)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *VsockEndpoint) Dst() *unix.SockaddrVM {
	return (*unix.SockaddrVM)(unsafe.Pointer(&endpoint.dst[0]))
}

func (end *VsockEndpoint) SrcIP() netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(end.Src().CID >> 24),
		byte(end.Src().CID >> 16),
		byte(end.Src().CID >> 8),
		byte(end.Src().CID),
	})
}

func (end *VsockEndpoint) DstIP() netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(end.Dst().CID >> 24),
		byte(end.Dst().CID >> 16),
		byte(end.Dst().CID >> 8),
		byte(end.Dst().CID),
	})
}

func (end *VsockEndpoint) DstToBytes() []byte {
	return []byte{
		byte(end.Dst().CID >> 24),
		byte(end.Dst().CID >> 16),
		byte(end.Dst().CID >> 8),
		byte(end.Dst().CID),
	}
}

func (end *VsockEndpoint) SrcToString() string {
	return fmt.Sprintf("vsock://%d:%d", end.Src().CID, end.Src().Port)
}

func (end *VsockEndpoint) DstToString() string {
	return fmt.Sprintf("vsock://%d:%d", end.Dst().CID, end.Dst().Port)
}

func (end *VsockEndpoint) ClearDst() {
	for i := range end.dst {
		end.dst[i] = 0
	}
}

func (end *VsockEndpoint) ClearSrc() {
	for i := range end.src {
		end.src[i] = 0
	}
}

func ParseEndpoint(s string) (conn.Endpoint, error) {
	var end VsockEndpoint

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "vsock" {
		return nil, fmt.Errorf("invalid scheme, expected 'vsock', got %s", u.Scheme)
	}
	cid, err := strconv.ParseUint(u.Hostname(), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid cid, expected an uint32, got %s", u.Hostname())
	}
	port, err := strconv.ParseUint(u.Port(), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port, expected an uint32, got %s", u.Port())
	}

	dst := end.Dst()
	dst.CID = uint32(cid)
	dst.Port = uint32(port)
	end.ClearSrc()
	return &end, nil
}
