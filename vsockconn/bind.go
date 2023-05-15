// Package vsockconn implements a WireGuard bind supporting TCP and VSOCK
// transport protocols.
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
	maxPacketSize     = 64 * 1024 // 64kb
	maxEnqueuePackets = 10

	defaultReconnectIntervalMin    = 500 * time.Millisecond
	defaultReconnectIntervalMax    = 30 * time.Second
	defaultReconnectIntervalFactor = 2

	// AnyCID can be used to check if the context ID of a VSOCK address is
	// equivalent to VMADDR_CID_ANY.
	AnyCID = math.MaxUint32

	// AnyCID can be used to check if the port of a VSOCK address is equivalent
	// to VMADDR_PORT_ANY.
	AnyPort = math.MaxUint32
)

var (
	_ conn.Bind     = (*vsockBind)(nil)
	_ conn.Endpoint = vsockEndpoint{}

	ErrInvalid = errors.New("invalid address")

	packetPool = sync.Pool{
		New: func() any {
			return make([]byte, maxPacketSize)
		},
	}

	ErrPacketTooLong = errors.New("packet is too long (>64kb)")
)

type vsockEndpoint struct {
	src net.Addr
	dst net.Addr
}

func (e vsockEndpoint) ClearSrc() {
	e.src = nil
}

func (e vsockEndpoint) DstIP() netip.Addr {
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

func (e vsockEndpoint) SrcIP() netip.Addr {
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

func (e vsockEndpoint) DstToBytes() []byte {
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

func (e vsockEndpoint) DstToString() string {
	if e.dst != nil {
		return e.dst.String()
	}
	return ""
}

func (e vsockEndpoint) SrcToString() string {
	if e.src != nil {
		return e.src.String()
	}
	return ""
}

// ParseVsockAddress returns the context ID and port of a VSOCK string address
// in the format
//
//	`\(hypervisor(0)|local(1)|host(\([2-9]|[1-9][0-9]+\))\):[0-9]*`
//
// Example:
//
//	vsockconn.ParseVsockAddress("host(2):12201")
//
// will return context ID 2 and port 12201.
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

type Option func(bind *vsockBind)

// WithReconnectIntervalMin returns an Option that defines the minimum interval
// to attempt reconnecting. Defaults to 500ms.
func WithReconnectIntervalMin(t time.Duration) Option {
	return func(bind *vsockBind) {
		bind.b.Min = t
	}
}

// WithReconnectIntervalMax returns an Option that defines the maximum interval
// to attempt reconnecting. Defaults to 30s.
func WithReconnectIntervalMax(t time.Duration) Option {
	return func(bind *vsockBind) {
		bind.b.Max = t
	}
}

// WithReconnectInterval returns an Option defining the multiplying factor for
// each increment step while reconnecting. Defaults to 2.
func WithReconnectIntervalFactor(factor float64) Option {
	return func(bind *vsockBind) {
		bind.b.Factor = factor
	}
}

// WithReconnectInterval returns an Option defining the jitter used at
// reconnecting. Jitter eases contention by randomizing backoff steps. Defaults
// to true.
func WithReconnectIntervalJitter(b bool) Option {
	return func(bind *vsockBind) {
		bind.b.Jitter = b
	}
}

// WithNetwork returns an Option to define thee network to be used while
// creating listening sockets and connecting to peers. It can be 'vsock' or
// 'tcp'. The 'tcp' option doesn't provide a much robust implementation of a
// WireGuard transport; it should be used only for testing purposes on
// architectures lacking VSOCK. Defaults to 'vsock'.
func WithNetwork(network string) Option {
	return func(bind *vsockBind) {
		bind.network = network
	}
}

type streamDatagram struct {
	b   []byte
	src net.Addr
}

type vsockBind struct {
	log *device.Logger

	wg     sync.WaitGroup
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	l net.Listener

	conns   map[string]net.Conn
	network string

	b       backoff.Backoff
	dialers map[string]interface{}
	pending map[string]*list.List

	received chan streamDatagram
}

func NewBind(logger *device.Logger, opts ...Option) conn.Bind {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	bind := &vsockBind{
		b: backoff.Backoff{
			Min:    defaultReconnectIntervalMin,
			Max:    defaultReconnectIntervalMax,
			Factor: defaultReconnectIntervalFactor,
			Jitter: true,
		},
		network:  "vsock",
		log:      logger,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[string]net.Conn),
		dialers:  make(map[string]interface{}),
		pending:  make(map[string]*list.List),
		received: make(chan streamDatagram),
	}

	for _, opt := range opts {
		opt(bind)
	}

	return bind
}

func (*vsockBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if len(s) > 0 {
		var end vsockEndpoint
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

func (bind *vsockBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.l != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// We don't listen if port is zero; it is an indication that the WireGuard
	// instance isn't a server. Client connections will be opened on demand at
	// the Send function.
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

func (bind *vsockBind) SetMark(value uint32) error {
	return nil
}

func (bind *vsockBind) Close() error {
	bind.mu.Lock()

	bind.cancel()

	var err error
	if bind.l != nil {
		err = bind.l.Close()
		bind.l = nil
	}
	for _, c := range bind.conns {
		c.Close()
	}

	bind.mu.Unlock()

	bind.wg.Wait()

	ctx := context.Background()
	bind.ctx, bind.cancel = context.WithCancel(ctx)
	return err
}

func (bind *vsockBind) Send(buff []byte, end conn.Endpoint) error {
	if len(buff) > maxPacketSize {
		return ErrPacketTooLong
	}

	se, ok := end.(*vsockEndpoint)
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
		b := packetPool.Get().([]byte)
		copy(b, buff)
		l.PushBack(b[:len(buff)])
		for l.Len() > maxEnqueuePackets {
			packetPool.Put(l.Front())
			l.Remove(l.Front())
		}

		return nil
	}

	return err
}

func (bind *vsockBind) lockedSend(b []byte, se *vsockEndpoint) (bool, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()

	conn, ok := bind.conns[se.dst.String()]
	if !ok {
		return false, nil
	}

	err := writePacketToConn(conn, b)
	if err != nil {
		return ok, err
	}

	return ok, nil
}

func writePacketToConn(conn net.Conn, b []byte) error {
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

func (bind *vsockBind) makeReceiveFunc() conn.ReceiveFunc {
	ctx := bind.ctx
	return func(b []byte) (int, conn.Endpoint, error) {
		select {
		case <-ctx.Done():
			return 0, nil, net.ErrClosed
		case d := <-bind.received:
			pktlen := len(d.b)
			copy(b[:pktlen], d.b)
			packetPool.Put(d.b)
			end := vsockEndpoint{dst: d.src}
			return pktlen, &end, nil
		}
	}
}

func (bind *vsockBind) serve() {
	bind.log.Verbosef("Routine: acceptor worker - started")
	defer bind.log.Verbosef("Routine: acceptor worker - stopped")

	defer bind.wg.Done()

	for {
		conn, err := bind.l.Accept()
		if err != nil {
			if _, ok := err.(*net.OpError); ok && !isClosedConnError(err) {
				bind.log.Verbosef("Accept error: %v", err)
			}
			return
		}
		bind.log.Verbosef("Routine: acceptor worker - new connection from: %v", conn.RemoteAddr())
		bind.handleConn(conn, nil, make(chan interface{}, 1))
	}
}

func (bind *vsockBind) handleConn(conn net.Conn, dst net.Addr, reconnect chan<- interface{}) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.conns[conn.RemoteAddr().String()] = conn

	// If there are pending frames, dispatch them all now

	if dst != nil {
		key := dst.String()
		l, ok := bind.pending[key]
		if ok {
			for l.Len() > 0 {
				ref := l.Front()
				b, _ := ref.Value.([]byte)

				err := writePacketToConn(conn, b)
				if err != nil {
					bind.log.Errorf("Error sending enqueued packets: %v", err)
					reconnect <- true
					return
				}

				packetPool.Put(b)
				l.Remove(ref)
			}
			delete(bind.pending, key)
		}
	}

	bind.wg.Add(1)
	go bind.read(bind.ctx, conn, reconnect)
}

func (bind *vsockBind) read(ctx context.Context, conn net.Conn, reconnect chan<- interface{}) {
	bind.log.Verbosef("Routine: reader worker - started")
	defer bind.log.Verbosef("Routine: reader worker - stopped")

	defer func() {
		bind.mu.Lock()
		defer bind.mu.Unlock()
		delete(bind.conns, conn.RemoteAddr().String())
		conn.Close()
	}()

	defer bind.wg.Done()

	for {
		b := packetPool.Get().([]byte)
		n, err := readPacketFromConn(conn, b)
		if err != nil {
			packetPool.Put(b)
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

func readPacketFromConn(conn net.Conn, b []byte) (int, error) {
	// Read the incoming packet's size as a binary value.
	_, err := io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, err
	}

	// Decode the incoming packet's size from binary.
	size := int(binary.LittleEndian.Uint16(b[:2]))

	// Read the packet, overriding the packet length.
	return io.ReadFull(conn, b[:size])
}

func (bind *vsockBind) dial(ctx context.Context, b backoff.Backoff, dst net.Addr) {
	bind.log.Verbosef("Routine: dialer worker - started")
	defer bind.log.Verbosef("Routine: dialer worker - stopped")

	defer bind.wg.Done()

	reconnect := make(chan interface{}, 1)

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
			if !isClosedConnError(err) {
				bind.log.Verbosef("Routine: dialer worker - failed dialing (%v), reconnecting in %s", err, d)
			}
			select {
			case <-bind.ctx.Done():
				return
			case <-time.After(d):
				continue
			}
		}

		bind.log.Verbosef("Routine: dialer worker - connected")

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

// isClosedConnError reports whether err is an error from use of a closed
// network connection.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	// Consider removing this string search when the standard library provides a
	// better way to do so.
	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}

	return false
}
