package vsockconn

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/backoff"
	"github.com/mdlayher/vsock"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	maxMTU              = 1500
	ethernetMinimumSize = 64

	defaultReconnectIntervalMin    = 500 * time.Millisecond
	defaultReconnectIntervalMax    = 30 * time.Second
	defaultReconnectIntervalFactor = 2

	AnyCID  = math.MaxUint32 // VMADDR_CID_ANY (-1U)
	AnyPort = math.MaxUint32 // VMADDR_PORT_ANY (-1U)
)

var (
	_ conn.Bind     = (*SocketStreamBind)(nil)
	_ conn.Endpoint = StreamEndpoint{}

	ErrInvalid = errors.New("invalid address")
)

type StreamEndpoint struct {
	src net.Addr
	dst net.Addr
}

func (e StreamEndpoint) ClearSrc() {
	e.src = nil
}

func (e StreamEndpoint) DstIP() netip.Addr {
	if e.dst != nil {
		switch dst := e.dst.(type) {
		case *net.TCPAddr:
			return dst.AddrPort().Addr()
		case *vsock.Addr:
			return netip.AddrFrom4([4]byte{
				byte(dst.ContextID >> 24),
				byte(dst.ContextID >> 16),
				byte(dst.ContextID >> 8),
				byte(dst.ContextID),
			})
		}
	}
	return netip.Addr{}
}

func (e StreamEndpoint) SrcIP() netip.Addr {
	if e.src != nil {
		switch src := e.src.(type) {
		case *net.TCPAddr:
			return src.AddrPort().Addr()
		case *vsock.Addr:
			return netip.AddrFrom4([4]byte{
				byte(src.ContextID >> 24),
				byte(src.ContextID >> 16),
				byte(src.ContextID >> 8),
				byte(src.ContextID),
			})
		}
	}
	return netip.Addr{}
}

func (e StreamEndpoint) DstToBytes() []byte {
	if e.dst != nil {
		switch dst := e.dst.(type) {
		case *net.TCPAddr:
			return dst.AddrPort().Addr().AsSlice()
		case *vsock.Addr:
			return []byte{
				byte(dst.ContextID >> 24),
				byte(dst.ContextID >> 16),
				byte(dst.ContextID >> 8),
				byte(dst.ContextID),
			}
		}
	}
	return []byte{}
}

func (e StreamEndpoint) DstToString() string {
	if e.dst != nil {
		return e.dst.String()
	}
	return ""
}

func (e StreamEndpoint) SrcToString() string {
	if e.src != nil {
		return e.src.String()
	}
	return ""
}

func ParseVsockAddress(s string) (uint32, uint32, error) {
	var err error
	var contextID, port uint64
	parts := strings.Split(s, ":")
	if parts[0] == "" {
		contextID = AnyCID
	} else if parts[0] == "hypervisor(0)" {
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
	if parts[1] == "" {
		port = AnyPort
	} else {
		port, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, ErrInvalid
		}
	}

	return uint32(contextID), uint32(port), nil
}

type Option func(bind *SocketStreamBind)

func ReconnectIntervalMin(t time.Duration) Option {
	return func(bind *SocketStreamBind) {
		bind.b.Min = t
	}
}

func ReconnectIntervalMax(t time.Duration) Option {
	return func(bind *SocketStreamBind) {
		bind.b.Max = t
	}
}

func ReconnectIntervalFactor(factor float64) Option {
	return func(bind *SocketStreamBind) {
		bind.b.Factor = factor
	}
}

func ReconnectIntervalJitter(b bool) Option {
	return func(bind *SocketStreamBind) {
		bind.b.Jitter = b
	}
}

func Network(network string) Option {
	return func(bind *SocketStreamBind) {
		bind.network = network
	}
}

type HandshakeFunc func(conn net.Conn) error

func Handshake(handshake HandshakeFunc) Option {
	return func(bind *SocketStreamBind) {
		bind.handshake = handshake
	}
}

type streamDatagram struct {
	b   []byte
	src net.Addr
}

type SocketStreamBind struct {
	log *device.Logger

	wg     sync.WaitGroup
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	l net.Listener

	conns   map[string]net.Conn
	pending map[string]*list.List
	network string

	b       backoff.Backoff
	dialers map[string]interface{}

	received chan streamDatagram

	handshake HandshakeFunc
}

func NewBind(logger *device.Logger, opts ...Option) conn.Bind {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	bind := &SocketStreamBind{
		b: backoff.Backoff{
			Min:    defaultReconnectIntervalMin,
			Max:    defaultReconnectIntervalMax,
			Factor: defaultReconnectIntervalFactor,
			Jitter: true,
		},
		network:   "vsock",
		log:       logger,
		ctx:       ctx,
		cancel:    cancel,
		conns:     make(map[string]net.Conn),
		dialers:   make(map[string]interface{}),
		pending:   make(map[string]*list.List),
		received:  make(chan streamDatagram),
		handshake: func(_ net.Conn) error { return nil },
	}

	for _, opt := range opts {
		opt(bind)
	}

	return bind
}

func (*SocketStreamBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if len(s) > 0 {
		var end StreamEndpoint
		if s[0] >= '0' && s[0] <= '9' {
			e, err := netip.ParseAddrPort(s)
			if err != nil {
				return nil, err
			}
			end.dst = net.TCPAddrFromAddrPort(e)
			return &end, nil
		} else {
			contextID, port, err := ParseVsockAddress(s)
			if err != nil {
				return nil, ErrInvalid
			}
			end.dst = &vsock.Addr{
				ContextID: uint32(contextID),
				Port:      uint32(port),
			}
			return &end, nil
		}
	}

	return nil, ErrInvalid
}

func (bind *SocketStreamBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.l != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if port != 0 {
		l, err := func() (net.Listener, error) {
			switch bind.network {
			case "tcp":
				return net.Listen("tcp", fmt.Sprintf(":%d", port))
			case "vsock":
				return vsock.ListenContextID(AnyCID, uint32(port), nil)
			default:
				panic(net.UnknownNetworkError(bind.network))
			}
		}()

		if err != nil {
			return nil, 0, err
		}

		bind.l = l
		bind.wg.Add(1)
		go bind.serve()
	}

	return []conn.ReceiveFunc{bind.makeReceiveFunc()}, port, nil
}

func (bind *SocketStreamBind) SetMark(value uint32) error {
	return nil
}

func (bind *SocketStreamBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.cancel()
	var err error
	if bind.l != nil {
		err = bind.l.Close()
		bind.l = nil
	}
	bind.wg.Wait()

	ctx := context.Background()
	bind.ctx, bind.cancel = context.WithCancel(ctx)
	return err
}

func (bind *SocketStreamBind) Send(buff []byte, end conn.Endpoint) error {
	se, ok := end.(*StreamEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	found, err := bind.lockedSend(buff, se)
	if !found {
		bind.mu.Lock()
		defer bind.mu.Unlock()

		key := se.dst.String()
		if _, ok := bind.dialers[key]; !ok {
			bind.dialers[key] = true
			bind.wg.Add(1)
			go bind.dial(bind.ctx, bind.b, se.dst)
		}

		l, ok := bind.pending[key]
		if !ok {
			l = list.New()
			bind.pending[key] = l
		}
		b := make([]byte, len(buff))
		copy(b, buff)
		l.PushBack(b)
		for l.Len() > 2 {
			l.Remove(l.Front())
		}

		return net.ErrClosed
	}

	return err
}

func (bind *SocketStreamBind) lockedSend(b []byte, se *StreamEndpoint) (bool, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()

	conn, ok := bind.conns[se.dst.String()]
	if !ok {
		return false, nil
	}

	err := bind.marshal(conn, b)
	if err != nil {
		return ok, err
	}

	return ok, nil
}

func (bind *SocketStreamBind) marshal(conn net.Conn, b []byte) error {
	// Write the packet's size.
	err := binary.Write(conn, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		return err
	}

	// Write as many bytes as required to send over the whole packet.
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}

	return nil
}

func (bind *SocketStreamBind) makeReceiveFunc() conn.ReceiveFunc {
	ctx := bind.ctx
	return func(b []byte) (int, conn.Endpoint, error) {
		select {
		case <-ctx.Done():
			return 0, nil, net.ErrClosed
		case d := <-bind.received:
			pktlen := len(d.b)
			copy(b[:pktlen], d.b)
			end := StreamEndpoint{dst: d.src}
			return pktlen, &end, nil
		}
	}
}

func (bind *SocketStreamBind) serve() {
	bind.log.Verbosef("Routine: listener worker - started")
	defer bind.log.Verbosef("Routine: listener worker - stopped")

	defer bind.wg.Done()

	for {
		conn, err := bind.l.Accept()
		if err != nil {
			if _, ok := err.(*net.OpError); ok {
				bind.log.Verbosef("Accept error: %v", err)
			}
			return
		}
		bind.log.Verbosef("New connection from: %v", conn.RemoteAddr())
		bind.handleConn(conn, nil, make(chan interface{}))
	}
}

func (bind *SocketStreamBind) handleConn(conn net.Conn, dst net.Addr, reconnect chan<- interface{}) {
	if err := bind.handshake(conn); err != nil {
		bind.log.Errorf("Handshake error %v", err)
		conn.Close()
		reconnect <- true
		return
	}

	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.conns[conn.RemoteAddr().String()] = conn
	bind.wg.Add(1)

	// If there are pending frames, dispatch them all now

	if dst != nil {
		key := dst.String()
		l, ok := bind.pending[key]
		if ok {
			for l.Len() > 0 {
				ref := l.Front()
				b, _ := ref.Value.([]byte)
				bind.marshal(conn, b)
				l.Remove(ref)
			}
			delete(bind.pending, key)
		}
	}

	go bind.read(bind.ctx, conn, reconnect)
}

func (bind *SocketStreamBind) read(ctx context.Context, conn net.Conn, reconnect chan<- interface{}) {
	bind.log.Verbosef("Routine: reader worker - started")
	defer bind.log.Verbosef("Routine: reader worker - stopped")

	defer func() {
		bind.mu.Lock()
		defer bind.mu.Unlock()
		delete(bind.conns, conn.RemoteAddr().String())
		conn.Close()
		bind.wg.Done()
	}()

	for {
		b := make([]byte, maxMTU+ethernetMinimumSize)
		n, err := bind.readFrame(conn, b)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				reconnect <- true
				return
			}
		}

		bind.received <- streamDatagram{b[:n], conn.RemoteAddr()}
	}
}

func (bind *SocketStreamBind) readFrame(conn net.Conn, b []byte) (int, error) {
	// Read the incoming packet's size as a binary value.
	n, err := io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, err
	}
	if n != 2 {
		return 0, io.EOF
	}

	// Decode the incoming packet's size from binary.
	size := int(binary.LittleEndian.Uint16(b[:2]))
	if size > len(b) {
		bind.log.Errorf("Error: attempted to write frame > %d: %d", len(b), size)
		conn.Close()
		return 0, net.ErrClosed
	}

	n, err = io.ReadFull(conn, b[:size])
	if err != nil {
		return 0, err
	}
	if n != size {
		return 0, io.EOF
	}

	return n, nil
}

func (bind *SocketStreamBind) dial(ctx context.Context, b backoff.Backoff, dst net.Addr) {
	bind.log.Verbosef("Routine: dialer worker - started")
	defer bind.log.Verbosef("Routine: dialer worker - stopped")

	defer bind.wg.Done()

	reconnect := make(chan interface{})

	for {
		conn, err := func() (net.Conn, error) {
			switch dst.Network() {
			case "tcp":
				var d net.Dialer
				return d.DialContext(bind.ctx, "tcp", dst.String())
			case "vsock":
				vsockAddr, _ := dst.(*vsock.Addr)
				return vsock.Dial(vsockAddr.ContextID, vsockAddr.Port, nil)
			default:
				panic(net.UnknownNetworkError(dst.Network()))
			}
		}()

		if err != nil {
			d := b.Duration()
			bind.log.Verbosef("Failed dialing (%v), reconnecting in %s", err, d)
			select {
			case <-bind.ctx.Done():
				return
			case <-time.After(d):
				continue
			}
		}

		b.Reset()
		bind.handleConn(conn, dst, reconnect)
		select {
		case <-bind.ctx.Done():
			return
		case <-reconnect:
			continue
		}
	}
}
