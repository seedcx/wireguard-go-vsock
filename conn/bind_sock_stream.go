package vsockconn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var (
	_ conn.Bind = (*SocketStreamBind)(nil)
)

type SocketStreamBind struct {
	log *device.Logger
	mu  sync.RWMutex
	l   *StreamListener
	c   *StreamConn
}

func NewSocketStreamBind(logger *device.Logger) conn.Bind {
	return &SocketStreamBind{log: logger}
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
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.l != nil || bind.c != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, 0, err
		}
		bind.l = NewStreamListener(l, bind.log)
	}

	return []conn.ReceiveFunc{bind.makeReceiveFunc()}, port, nil
}

func (bind *SocketStreamBind) SetMark(value uint32) error {
	return nil
}

func (bind *SocketStreamBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.l != nil {
		bind.l.Close()
	}
	if bind.c != nil {
		bind.c.Close()
	}
	return nil
}

func (bind *SocketStreamBind) Send(buff []byte, end conn.Endpoint) error {
	_, ok := end.(*SockaddrInet4Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	bind.mu.RLock()
	defer bind.mu.RUnlock()

	if bind.l != nil {
		return bind.l.Write(buff)
	}

	if bind.c == nil {
		bind.mu.RUnlock()
		err := bind.lockedConnect(end)
		if err != nil {
			return nil
		}
		bind.mu.RLock()
	}

	err := bind.c.Write(buff)
	if err != nil {
		bind.lockedDisconnect()
	}
	return err
}

func (bind *SocketStreamBind) lockedConnect(end conn.Endpoint) error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	// Already connected
	if bind.c != nil {
		return nil
	}

	conn, err := net.Dial("tcp", end.DstToString())
	if err != nil {
		return err
	}

	bind.c = NewStreamConn(conn, bind.log)
	return nil
}

func (bind *SocketStreamBind) lockedDisconnect() {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	// Already disconnected
	if bind.c == nil {
		return
	}

	bind.c.Close()
	bind.c = nil
}

func (bind *SocketStreamBind) makeReceiveFunc() conn.ReceiveFunc {
	return func(b []byte) (int, conn.Endpoint, error) {
		bind.mu.RLock()
		defer bind.mu.RUnlock()

	again:
		n, rAddr, err := func() (int, net.Addr, error) {
			for {
				if bind.l != nil {
					return bind.l.Read(b)
				}
				if bind.c != nil {
					return bind.c.Read(b)
				}
				bind.mu.RUnlock()
				time.Sleep(1 * time.Second)
				bind.mu.RLock()
			}
		}()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, unix.ECONNRESET) {
				bind.mu.RUnlock()
				time.Sleep(1 * time.Second)
				bind.mu.RLock()
				goto again
			}
			return 0, nil, err
		}

		end, _ := bind.ParseEndpoint(rAddr.String())
		endInet4, _ := end.(*SockaddrInet4Endpoint)
		*endInet4.Src4() = *endInet4.Dst4()
		endInet4.ClearDst()

		return n, endInet4, nil
	}
}
