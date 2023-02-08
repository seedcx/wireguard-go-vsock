package vsockconn

import (
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	listenBacklog = 1024
)

var (
	_ conn.Bind = (*VsockStreamBind)(nil)
)

type VsockStreamBind struct {
	log *device.Logger

	// mu guards sockets
	mu sync.RWMutex
	wg sync.WaitGroup

	listen_sock int

	conn_sock int
	conn_end  VsockEndpoint
}

func NewVsockStreamBind(logger *device.Logger) conn.Bind {
	return &VsockStreamBind{log: logger, listen_sock: -1, conn_sock: -1}
}

func (*VsockStreamBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return ParseEndpoint(s)
}

func (bind *VsockStreamBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
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

func (bind *VsockStreamBind) OpenContextID(cid, port uint32) ([]conn.ReceiveFunc, uint32, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.listen_sock != -1 {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if port == AnyPort {
		// In client mode, we'll wait for the peer address at the Send function
		bind.wg.Add(1)
	} else {
		fd, err := createVsockStreamAndListen(cid, port)
		if err != nil {
			return nil, 0, err
		}
		bind.listen_sock = fd
		bind.startAccepting()
	}

	return []conn.ReceiveFunc{bind.makeReceiveFunc()}, port, nil
}

func (bind *VsockStreamBind) SetMark(value uint32) error {
	return nil
}

func (bind *VsockStreamBind) Close() error {
	// Take a readlock to shut down the sockets...
	bind.mu.RLock()
	if bind.conn_sock != -1 {
		unix.Shutdown(bind.conn_sock, unix.SHUT_RDWR)
	}
	bind.mu.RUnlock()
	// ...and a write lock to close the fds.
	// This ensures that no one else is using the fd.
	bind.mu.Lock()
	defer bind.mu.Unlock()
	var err error
	if bind.conn_sock != -1 {
		err = unix.Close(bind.conn_sock)
		bind.conn_sock = -1
		bind.conn_end.ClearDst()
		bind.wg.Add(1)
	}
	if bind.listen_sock != -1 {
		// By closing the socket here, we'll trigger acceptor closure.
		unix.Close(bind.listen_sock)
		bind.listen_sock = -1
	}
	return err
}

func (bind *VsockStreamBind) Send(buff []byte, end conn.Endpoint) error {
	nend, ok := end.(*VsockEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	bind.mu.RLock()
	defer bind.mu.RUnlock()

	if bind.conn_sock == -1 {
		if bind.listen_sock == -1 {
			// In client mode, we connect to the peer
			bind.mu.Lock()
			defer bind.mu.Unlock()
			fd, err := createVsockStreamAndConnect(nend)
			if err != nil {
				return err
			}
			bind.conn_sock = fd
			*bind.conn_end.Dst() = *nend.Dst()
			bind.wg.Done()
		} else {
			// In listening mode, we'll wait for a connection
			return net.ErrClosed
		}
	} else {
		if *nend.Dst() != *bind.conn_end.Dst() {
			bind.log.Verbosef("multiple peers is not supported")
			return net.ErrClosed
		}
	}

	err := unix.Send(bind.conn_sock, buff, 0)
	if err != nil {
		bind.mu.Lock()
		defer bind.mu.Unlock()
		if bind.conn_sock != -1 {
			unix.Close(bind.conn_sock)
			bind.conn_sock = -1
			bind.conn_end.ClearDst()
			bind.wg.Add(1)
		}
		return err
	}

	return nil
}

func (bind *VsockStreamBind) startAccepting() {
	bind.wg.Add(1)

	go func() {
		for {
			nfd, newDst, err := unix.Accept(bind.listen_sock)
			if err != nil {
				bind.mu.Lock()
				defer bind.mu.Unlock()
				if bind.listen_sock != -1 {
					bind.log.Errorf("Failed to accept, shutdown loop: %v", err)
					unix.Close(bind.listen_sock)
					bind.listen_sock = -1
				}
				break
			}

			bind.mu.Lock()
			if bind.conn_sock == -1 {
				bind.wg.Done()
			} else {
				// In this case we don't bind.wg.Add(1) because
				// it is an atomic substitution
				unix.Close(bind.conn_sock)
			}
			bind.conn_sock = nfd
			newDstVM, _ := newDst.(*unix.SockaddrVM)
			*bind.conn_end.Dst() = *newDstVM
			bind.mu.Unlock()
		}

		bind.log.Verbosef("Shutdown accept loop")
	}()
}

func (bind *VsockStreamBind) makeReceiveFunc() conn.ReceiveFunc {
	return func(b []byte) (int, conn.Endpoint, error) {
		bind.wg.Wait()
		n, end, err := bind.receive(b)
		if err != nil {
			bind.mu.Lock()
			defer bind.mu.Unlock()
			if bind.conn_sock != -1 {
				unix.Close(bind.conn_sock)
				bind.conn_sock = -1
				bind.conn_end.ClearDst()
				bind.wg.Add(1)
			}
			return 0, nil, err
		}
		return n, end, nil
	}
}

func (bind *VsockStreamBind) receive(b []byte) (int, conn.Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.conn_sock == -1 {
		return 0, nil, net.ErrClosed
	}
	var end VsockEndpoint
	n, newDst, err := unix.Recvfrom(bind.conn_sock, b, 0)
	if err == nil {
		if newDstVM, ok := newDst.(*unix.SockaddrVM); ok {
			*end.Dst() = *newDstVM
		}
	}
	return n, &end, err
}

func createVsockStreamAndConnect(nend *VsockEndpoint) (int, error) {
	fd, err := unix.Socket(
		unix.AF_VSOCK,
		unix.SOCK_STREAM,
		0,
	)
	if err != nil {
		return -1, err
	}

	err = unix.Connect(fd, nend.Dst())
	if err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func createVsockStreamAndListen(cid, port uint32) (int, error) {
	// create socket

	fd, err := unix.Socket(
		unix.AF_VSOCK,
		unix.SOCK_STREAM,
		0,
	)
	if err != nil {
		return -1, err
	}

	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	// bind and listen

	if err := unix.Bind(fd, &addr); err != nil {
		unix.Close(fd)
		return -1, err
	}

	if err := unix.Listen(fd, listenBacklog); err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, err
}
