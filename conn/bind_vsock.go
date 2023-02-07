package vsockconn

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	anyCID  = math.MaxUint32 // VMADDR_CID_ANY (-1U)
	anyPort = math.MaxUint32 // VMADDR_PORT_ANY (-1U)
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
	return end.SrcIP().String()
}

func (end *VsockEndpoint) DstToString() string {
	return netip.AddrPortFrom(end.DstIP(), uint16(end.Dst().Port)).String()
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

type VsockBind struct {
	// mu guards vs.
	mu   sync.RWMutex
	sock int
}

func NewVsockSocketBind() conn.Bind { return &VsockBind{} }

var (
	_ conn.Endpoint = (*VsockEndpoint)(nil)
	_ conn.Bind     = (*VsockBind)(nil)
)

func (*VsockBind) ParseEndpoint(s string) (conn.Endpoint, error) {
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

func (bind *VsockBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// TODO(balena): VSOCK ports are 32-bits, this may break at corner cases, but
	// in general apps can use 16-bit ones.
	fns, newPort, err := bind.OpenContextID(anyCID, uint32(port))
	return fns, *(*uint16)(unsafe.Pointer(&newPort)), err
}

func (bind *VsockBind) OpenContextID(cid, port uint32) ([]conn.ReceiveFunc, uint32, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var newPort uint32
	var tries int

	originalPort := port

again:
	port = originalPort

	sock, newPort, err := createVsock(cid, port)
	if err != nil {
		if originalPort == anyPort && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			unix.Close(sock)
			tries++
			goto again
		}
		if !errors.Is(err, syscall.EAFNOSUPPORT) {
			unix.Close(sock)
			return nil, 0, err
		}
	} else {
		port = newPort
	}

	bind.sock = sock
	fns := []conn.ReceiveFunc{bind.receiveVsock}
	return fns, port, nil
}

func (bind *VsockBind) SetMark(value uint32) error {
	return nil
}

func (bind *VsockBind) Close() error {
	// Take a readlock to shut down the sockets...
	bind.mu.RLock()
	if bind.sock != -1 {
		unix.Shutdown(bind.sock, unix.SHUT_RDWR)
	}
	bind.mu.RUnlock()
	// ...and a write lock to close the fd.
	// This ensures that no one else is using the fd.
	bind.mu.Lock()
	defer bind.mu.Unlock()
	var err error
	if bind.sock != -1 {
		err = unix.Close(bind.sock)
		bind.sock = -1
	}
	return err
}

func (bind *VsockBind) Send(buff []byte, end conn.Endpoint) error {
	nend, ok := end.(*VsockEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.sock == -1 {
		return net.ErrClosed
	}
	return sendVsock(bind.sock, nend, buff)
}

func createVsock(cid, port uint32) (int, uint32, error) {
	// create socket

	fd, err := unix.Socket(
		unix.AF_VSOCK,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return -1, 0, err
	}

	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	// set sockopts and bind

	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}

	sa, err := unix.Getsockname(fd)
	if err == nil {
		addr.Port = sa.(*unix.SockaddrVM).Port
	}

	return fd, addr.Port, err
}

func sendVsock(sock int, end *VsockEndpoint, buff []byte) error {
	end.mu.Lock()
	defer end.mu.Unlock()

	return unix.Sendto(sock, buff, 0, end.Dst())
}

func (bind *VsockBind) receiveVsock(buf []byte) (int, conn.Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.sock == -1 {
		return 0, nil, net.ErrClosed
	}
	n, newDst, err := unix.Recvfrom(bind.sock, buf, 0)
	if err != nil {
		return 0, nil, err
	}
	var end VsockEndpoint
	if newDstVM, ok := newDst.(*unix.SockaddrVM); ok {
		*end.Dst() = *newDstVM
	}
	return n, &end, err
}
