package vsockconn

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var (
	_ conn.Bind = (*SocketStreamBind)(nil)
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

type SocketStreamBind struct {
	log *device.Logger

	// mu guards sockets
	mu sync.RWMutex
	wg sync.WaitGroup

	listen_sock int

	conn_sock int
	conn_end  SockaddrInet4Endpoint
}

func NewSocketStreamBind(logger *device.Logger) conn.Bind {
	return &SocketStreamBind{log: logger, listen_sock: -1, conn_sock: -1}
}

func (*SocketStreamBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	var end SockaddrInet4Endpoint
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}

	if e.Addr().Is4() {
		dst := end.dst4()
		dst.Port = int(e.Port())
		dst.Addr = e.Addr().As4()
		end.ClearSrc()
		return &end, nil
	}

	return nil, errors.New("invalid IP address")
}

func (bind *SocketStreamBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.log.Verbosef("Open %v", port)

	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.listen_sock != -1 {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if port == 0 {
		// As client, we'll connect at the Send function
		bind.wg.Add(1)
	} else {
		fd, err := listen(port)
		bind.log.Verbosef("listen — %v, %v, %v", fd, err)
		if err != nil {
			return nil, 0, err
		}
		bind.listen_sock = fd
		bind.wg.Add(1)
		go func() {
			for {
				nfd, newDst, err := accept(bind.listen_sock)
				bind.log.Verbosef("Accept — %v, %v, %v", nfd, newDst, err)
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
					// bind.wg.Add(1) occurs when:
					// - first listen
					// - whenever the peer connection drops
					bind.wg.Done()
				} else {
					// In this case we don't bind.wg.Done() because
					// it is an atomic substitution
					unix.Close(bind.conn_sock)
				}
				bind.conn_sock = nfd
				*bind.conn_end.dst4() = *newDst
				bind.mu.Unlock()
			}

			bind.log.Verbosef("Shutdown accept loop")
		}()
	}

	return []conn.ReceiveFunc{bind.makeReceiveFunc()}, port, nil
}

func (bind *SocketStreamBind) SetMark(value uint32) error {
	return nil
}

func (bind *SocketStreamBind) Close() error {
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
		bind.wg.Add(1)
	}
	if bind.listen_sock != -1 {
		// By closing the socket here, we'll trigger acceptor closure.
		unix.Close(bind.listen_sock)
		bind.listen_sock = -1
	}
	return err
}

func (bind *SocketStreamBind) Send(buff []byte, end conn.Endpoint) error {
	nend, ok := end.(*SockaddrInet4Endpoint)
	if !ok {
		bind.log.Verbosef("Wrong endpoint type %T", end)
		return conn.ErrWrongEndpointType
	}

	bind.mu.RLock()
	if bind.conn_sock == -1 {
		if bind.listen_sock == -1 {
			// In client mode, we connect to the peer
			bind.mu.RUnlock()
			bind.mu.Lock()
			fd, err := dial(nend.dst4())
			if err != nil {
				bind.mu.Unlock()
				if err == unix.ECONNREFUSED {
					return nil
				} else {
					return err
				}
			}
			bind.conn_sock = fd
			*bind.conn_end.dst4() = *nend.dst4()
			bind.wg.Done()
			bind.mu.Unlock()
		} else {
			// In listening mode, we'll wait for a connection
			bind.mu.RUnlock()
			return net.ErrClosed
		}
	} else {
		if *nend.dst4() != *bind.conn_end.dst4() {
			bind.mu.RUnlock()
			bind.log.Verbosef("multiple peers is not supported")
			return net.ErrClosed
		}
	}

	err := unix.Send(bind.conn_sock, buff, 0)
	bind.log.Verbosef("unix.Send — %v", err)
	bind.mu.RUnlock()

	if err != nil {
		bind.mu.Lock()
		if bind.conn_sock != -1 {
			unix.Close(bind.conn_sock)
			bind.conn_sock = -1
			bind.conn_end.ClearDst()
			bind.wg.Add(1)
		}
		bind.mu.Unlock()
		return err
	}

	return nil
}

func (bind *SocketStreamBind) makeReceiveFunc() conn.ReceiveFunc {
	return func(b []byte) (int, conn.Endpoint, error) {
		bind.wg.Wait()
		n, end, err := bind.receive(b)
		bind.log.Verbosef("receive — %v, %v, %v", n, end, err)
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

func (bind *SocketStreamBind) receive(b []byte) (int, conn.Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.conn_sock == -1 {
		return 0, nil, net.ErrClosed
	}
	var end SockaddrInet4Endpoint
	n, newDst, err := unix.Recvfrom(bind.conn_sock, b, 0)
	if err == nil {
		if newDst4, ok := newDst.(*unix.SockaddrInet4); ok {
			*end.dst4() = *newDst4
		}
	}
	return n, &end, err
}

func dial(sa *unix.SockaddrInet4) (int, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_STREAM|socketFlags,
		0,
	)
	if err != nil {
		return -1, err
	}

	err = unix.Connect(fd, sa)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func listen(port uint16) (int, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_STREAM|socketFlags,
		0,
	)
	if err != nil {
		return -1, err
	}

	addr := unix.SockaddrInet4{
		Port: int(port),
	}

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

func accept(sock int) (int, *unix.SockaddrInet4, error) {
	nfd, newDst, err := unix.Accept(sock)
	if err != nil {
		return -1, nil, err
	}
	newDstVM, _ := newDst.(*unix.SockaddrInet4)
	return nfd, newDstVM, nil
}
