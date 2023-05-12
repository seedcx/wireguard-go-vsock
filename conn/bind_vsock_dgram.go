package vsockconn

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

var (
	_ conn.Bind = (*VsockDgramBind)(nil)
)

type VsockDgramBind struct {
	// mu guards vs.
	mu   sync.RWMutex
	sock int
}

func NewVsockDgramBind() conn.Bind { return &VsockDgramBind{sock: -1} }

func (*VsockDgramBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	contextID, port, err := ParseVsockAddress(s)
	if err != nil {
		return nil, err
	}
	var end VsockEndpoint
	dst := end.Dst()
	dst.CID = contextID
	dst.Port = port
	return &end, nil
}

func (bind *VsockDgramBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// TODO(balena): VSOCK ports are 32-bits, this may break at corner cases, but
	// in general apps can use 16-bit ones. We also convert the AF_INET port 0 to
	// AnyPort (-1U).
	var port32 uint32
	if port == 0 {
		port32 = AnyPort
	} else {
		port32 = uint32(port)
	}
	fns, newPort, err := bind.OpenContextID(AnyCID, port32)
	return fns, *(*uint16)(unsafe.Pointer(&newPort)), err
}

func (bind *VsockDgramBind) OpenContextID(cid, port uint32) ([]conn.ReceiveFunc, uint32, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var newPort uint32
	var tries int

	if bind.sock != -1 {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	originalPort := port

again:
	port = originalPort

	sock, newPort, err := createVsockDgram(cid, port)
	if err != nil {
		if originalPort == AnyPort && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
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
	fns := []conn.ReceiveFunc{bind.receiveVsockDgram}
	return fns, port, nil
}

func (bind *VsockDgramBind) SetMark(value uint32) error {
	return nil
}

func (bind *VsockDgramBind) Close() error {
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

func (bind *VsockDgramBind) Send(buff []byte, end conn.Endpoint) error {
	nend, ok := end.(*VsockEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.sock == -1 {
		return net.ErrClosed
	}
	return unix.Sendto(bind.sock, buff, 0, nend.Dst())
}

func createVsockDgram(cid, port uint32) (int, uint32, error) {
	// create socket

	fd, err := unix.Socket(
		unix.AF_VSOCK,
		unix.SOCK_DGRAM|socketFlags,
		0,
	)
	if err != nil {
		return -1, 0, err
	}

	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	// bind and double check the bound port

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

func (bind *VsockDgramBind) receiveVsockDgram(buf []byte) (int, conn.Endpoint, error) {
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
