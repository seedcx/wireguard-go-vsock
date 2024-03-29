// Package vsockconn implements a WireGuard bind supporting TCP and VSOCK
// transport protocols.
package vsockconn

import (
	"bufio"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
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
	_ conn.Bind     = (*VSOCKBind)(nil)
	_ conn.Endpoint = (*VSOCKEndpoint)(nil)

	ErrInvalid       = errors.New("invalid address")
	ErrPacketTooLong = errors.New("packet is too long (>64kb)")
	ErrBadCRC        = errors.New("bad packet checksum")
)

type VSOCKEndpoint struct {
	src net.Addr
	dst net.Addr
}

func (e *VSOCKEndpoint) ClearSrc() {
	e.src = nil
}

func (e VSOCKEndpoint) DstIP() netip.Addr {
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

func (e VSOCKEndpoint) SrcIP() netip.Addr {
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

func (e VSOCKEndpoint) DstToBytes() []byte {
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

func (e VSOCKEndpoint) DstToString() string {
	if e.dst != nil {
		return e.dst.String()
	}
	return ""
}

func (e VSOCKEndpoint) SrcToString() string {
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
	} else if parts[0][0] >= '0' && parts[0][0] <= '9' {
		ip, err := netip.ParseAddr(parts[0])
		if err != nil {
			return 0, 0, err
		}
		for _, b := range ip.AsSlice() {
			contextID = (contextID << 8) + uint64(b)
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

type Option func(bind *VSOCKBind)

// WithReconnectIntervalMin returns an Option that defines the minimum interval
// to attempt reconnecting. Defaults to 500ms.
func WithReconnectIntervalMin(t time.Duration) Option {
	return func(bind *VSOCKBind) {
		bind.b.Min = t
	}
}

// WithReconnectIntervalMax returns an Option that defines the maximum interval
// to attempt reconnecting. Defaults to 30s.
func WithReconnectIntervalMax(t time.Duration) Option {
	return func(bind *VSOCKBind) {
		bind.b.Max = t
	}
}

// WithReconnectInterval returns an Option defining the multiplying factor for
// each increment step while reconnecting. Defaults to 2.
func WithReconnectIntervalFactor(factor float64) Option {
	return func(bind *VSOCKBind) {
		bind.b.Factor = factor
	}
}

// WithReconnectInterval returns an Option defining the jitter used at
// reconnecting. Jitter eases contention by randomizing backoff steps. Defaults
// to true.
func WithReconnectIntervalJitter(b bool) Option {
	return func(bind *VSOCKBind) {
		bind.b.Jitter = b
	}
}

// WithNetwork returns an Option to define thee network to be used while
// creating listening sockets and connecting to peers. It can be 'vsock' or
// 'tcp'. The 'tcp' option doesn't provide a much robust implementation of a
// WireGuard transport; it should be used only for testing purposes on
// architectures lacking VSOCK. Defaults to 'vsock'.
func WithNetwork(network string) Option {
	return func(bind *VSOCKBind) {
		bind.network = network
	}
}

type streamDatagram struct {
	b   []byte
	src net.Addr
}

type VSOCKBind struct {
	log *device.Logger

	wg     sync.WaitGroup
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	l net.Listener

	conns   map[string]net.Conn
	network string

	b       backoff.Backoff
	dialers map[string]any
	pending map[string]*list.List

	received chan streamDatagram

	packetPool sync.Pool
}

func NewBind(logger *device.Logger, opts ...Option) conn.Bind {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	bind := &VSOCKBind{
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
		dialers:  make(map[string]any),
		pending:  make(map[string]*list.List),
		received: make(chan streamDatagram),
		packetPool: sync.Pool{
			New: func() any {
				s := make([]byte, maxPacketSize)
				return &s
			},
		},
	}

	for _, opt := range opts {
		opt(bind)
	}

	return bind
}

func (bind *VSOCKBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if len(s) == 0 {
		return nil, ErrInvalid
	}

	var end VSOCKEndpoint
	switch bind.network {
	case "vsock":
		contextID, port, err := ParseVsockAddress(s)
		if err != nil {
			return nil, ErrInvalid
		}
		end.dst = &vsock.Addr{
			ContextID: uint32(contextID),
			Port:      uint32(port),
		}
	case "tcp", "tcp4", "tcp6":
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		end.dst = net.TCPAddrFromAddrPort(e)
	default:
		return nil, net.UnknownNetworkError(bind.network)
	}
	return &end, nil
}

func (bind *VSOCKBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
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
			case "tcp", "tcp4", "tcp6":
				return net.Listen(bind.network, fmt.Sprintf(":%d", port))
			case "vsock":
				return vsock.ListenContextID(AnyCID, uint32(port), nil)
			default:
				return nil, net.UnknownNetworkError(bind.network)
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

func (bind *VSOCKBind) SetMark(value uint32) error {
	return nil
}

func (bind *VSOCKBind) Close() error {
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

func (s *VSOCKBind) BatchSize() int {
	return 1
}

func (bind *VSOCKBind) Send(bufs [][]byte, end conn.Endpoint) error {
	for _, buff := range bufs {
		err := bind.send(buff, end)
		if err != nil {
			return err
		}
	}
	return nil
}

func (bind *VSOCKBind) send(buff []byte, end conn.Endpoint) error {
	if len(buff) > maxPacketSize {
		return ErrPacketTooLong
	}

	se, ok := end.(*VSOCKEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	found, err := bind.lockedSend(buff, se)
	if err != nil {
		return err
	}
	if found {
		return nil
	}

	bind.mu.Lock()
	defer bind.mu.Unlock()

	key := se.dst.String()
	if _, ok := bind.dialers[key]; !ok {
		bind.dialers[key] = true
		bind.wg.Add(1)
		go bind.dial(se.dst)
	}

	l, ok := bind.pending[key]
	if !ok {
		l = list.New()
		bind.pending[key] = l
	}
	ptr := bind.packetPool.Get().(*[]byte)
	b := *ptr
	b = b[:maxPacketSize]
	copy(b, buff)
	l.PushBack(b[:len(buff)])
	for l.Len() > maxEnqueuePackets {
		b = l.Front().Value.([]byte)
		bind.packetPool.Put(&b)
		l.Remove(l.Front())
	}

	return nil
}

func (bind *VSOCKBind) lockedSend(b []byte, se *VSOCKEndpoint) (bool, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()

	conn, ok := bind.conns[se.dst.String()]
	if !ok {
		return false, nil
	}

	err := writePacket(conn, b)
	if err != nil {
		return ok, err
	}

	return ok, nil
}

func writePacket(w io.Writer, b []byte) error {
	// Write the packet's size.
	size := uint16(len(b))
	err := binary.Write(w, binary.LittleEndian, &size)
	if err != nil {
		return err
	}

	// Write the packet's CRC
	crc := crc32.ChecksumIEEE(b)
	err = binary.Write(w, binary.LittleEndian, &crc)
	if err != nil {
		return err
	}

	// Write as many bytes as required to send over the whole packet.
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}

	return nil
}

func (bind *VSOCKBind) makeReceiveFunc() conn.ReceiveFunc {
	ctx := bind.ctx
	received := bind.received
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case d := <-received:
			sizes[0] = len(d.b)
			copy(packets[0], d.b)
			bind.packetPool.Put(&d.b)
			eps[0] = &VSOCKEndpoint{dst: d.src}
			return 1, nil
		}
	}
}

func (bind *VSOCKBind) serve() {
	bind.log.Verbosef("Routine: acceptor worker - started")
	defer bind.log.Verbosef("Routine: acceptor worker - stopped")

	defer bind.wg.Done()

	for {
		bind.mu.Lock()
		l := bind.l
		bind.mu.Unlock()

		if l == nil {
			return
		}

		conn, err := l.Accept()
		if err != nil {
			if _, ok := err.(*net.OpError); ok && !isClosedConnError(err) {
				bind.log.Verbosef("Accept error: %v", err)
			}
			return
		}

		bind.log.Verbosef("Routine: acceptor worker - new connection from: %v", conn.RemoteAddr())
		bind.handleConn(conn, make(chan any, 1))
	}
}

func (bind *VSOCKBind) handleConn(conn net.Conn, reconnect chan<- any) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	key := conn.RemoteAddr().String()
	bind.conns[key] = conn

	// If there are pending frames, dispatch them all now

	l, ok := bind.pending[key]
	if ok {
		for l.Len() > 0 {
			b := l.Front().Value.([]byte)

			err := writePacket(conn, b)
			if err != nil {
				bind.log.Errorf("Error sending enqueued packets: %v", err)
				reconnect <- true
				return
			}

			bind.packetPool.Put(&b)
			l.Remove(l.Front())
		}
		delete(bind.pending, key)
	}

	bind.wg.Add(1)
	go bind.read(bind.ctx, conn, reconnect)
}

func (bind *VSOCKBind) read(ctx context.Context, conn net.Conn, reconnect chan<- any) {
	bind.log.Verbosef("Routine: reader worker - started")
	defer bind.log.Verbosef("Routine: reader worker - stopped")

	remoteAddr := conn.RemoteAddr()

	defer func() {
		bind.wg.Done()

		bind.mu.Lock()
		delete(bind.conns, remoteAddr.String())
		conn.Close()
		bind.mu.Unlock()
	}()

	r := bufio.NewReaderSize(conn, maxPacketSize)
	for {
		ptr := bind.packetPool.Get().(*[]byte)
		b := *ptr
		b = b[:maxPacketSize]
		n, err := readPacket(r, b)
		if err != nil {
			bind.packetPool.Put(&b)
			select {
			case <-ctx.Done():
				return
			default:
				bind.log.Verbosef("Routine: reader worker - error %v, reconnecting")
				reconnect <- true
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case bind.received <- streamDatagram{b[:n], remoteAddr}:
		}
	}
}

func readPacket(r io.Reader, b []byte) (int, error) {
	// Read the incoming packet's size as a binary value.
	var size uint16
	err := binary.Read(r, binary.LittleEndian, &size)
	if err != nil {
		return 0, err
	}

	// Read the incoming packet's CRC.
	var crc uint32
	err = binary.Read(r, binary.LittleEndian, &crc)
	if err != nil {
		return 0, err
	}

	// Read the packet, overriding the packet length.
	b = b[:size]
	n, err := io.ReadFull(r, b)
	if err != nil {
		return 0, err
	}
	if crc != crc32.ChecksumIEEE(b) {
		return 0, ErrBadCRC
	}

	return n, nil
}

func (bind *VSOCKBind) dial(dst net.Addr) {
	bind.log.Verbosef("Routine: dialer worker - started")
	defer bind.log.Verbosef("Routine: dialer worker - stopped")

	defer func() {
		bind.wg.Done()

		bind.mu.Lock()
		key := dst.String()
		delete(bind.dialers, key)
		bind.mu.Unlock()
	}()

	reconnect := make(chan any, 1)

	b := bind.b
	t := time.NewTimer(0)
	for {
		conn, err := func() (net.Conn, error) {
			switch dst.Network() {
			case "tcp", "tcp4", "tcp6":
				var d net.Dialer
				return d.DialContext(bind.ctx, bind.network, dst.String())
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
			t.Reset(d)
			select {
			case <-bind.ctx.Done():
				return
			case <-t.C:
				continue
			}
		}

		bind.log.Verbosef("Routine: dialer worker - connected")

		b.Reset()
		bind.handleConn(conn, reconnect)
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
	return strings.Contains(err.Error(), "use of closed network connection")
}
