package vsockconn

import (
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	AnyCID  = math.MaxUint32 // VMADDR_CID_ANY (-1U)
	AnyPort = math.MaxUint32 // VMADDR_PORT_ANY (-1U)
)

var (
	_ conn.Endpoint = (*VsockEndpoint)(nil)

	ErrInvalid = errors.New("invalid address")
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
	addr := vsock.Addr{ContextID: end.Src().CID, Port: end.Src().Port}
	return addr.String()
}

func (end *VsockEndpoint) DstToString() string {
	addr := vsock.Addr{ContextID: end.Dst().CID, Port: end.Dst().Port}
	return addr.String()
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

func ParseVsockAddress(s string) (uint32, uint32, error) {
	var err error
	var contextID, port uint64
	parts := strings.Split(s, ":")
	if parts[0] == "hypervisor(0)" {
		contextID = 0
	} else if parts[0] == "local(1)" {
		contextID = 1
	} else if parts[0] == "host(2)" {
		contextID = 2
	} else if strings.HasPrefix(parts[0], "vm(") && parts[0][len(parts[0])-1] == ')' {
		contextID, err = strconv.ParseUint(parts[0][3:len(parts[0])-1], 10, 32)
		if err != nil {
			return 0, 0, ErrInvalid
		} else if contextID < 3 {
			return 0, 0, ErrInvalid
		}
	} else {
		return 0, 0, ErrInvalid
	}
	port, err = strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, ErrInvalid
	}

	return uint32(contextID), uint32(port), nil
}
