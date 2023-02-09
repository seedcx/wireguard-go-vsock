package vsockconn

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/device"
)

type StreamConn struct {
	conn       net.Conn
	quit       chan interface{}
	mu         sync.RWMutex
	log        *device.Logger
	remoteAddr net.Addr
}

func NewStreamConn(conn net.Conn, logger *device.Logger) *StreamConn {
	return &StreamConn{
		quit:       make(chan interface{}),
		conn:       conn,
		log:        logger,
		remoteAddr: conn.RemoteAddr(),
	}
}

func (c *StreamConn) Write(b []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Write the packet's size.
	err := binary.Write(c.conn, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		return err
	}

	// Write as many bytes as required to send over the whole packet.
	for len(b) > 0 {
		n, err := c.conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}

	return nil
}

func (c *StreamConn) Read(b []byte) (int, net.Addr, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Read the incoming packet's size as a binary value.
	n, err := io.ReadFull(c.conn, b[:2])
	if err != nil {
		select {
		case <-c.quit:
			return 0, nil, net.ErrClosed
		default:
			if err == io.EOF {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, err
		}
	}
	if n != 2 {
		c.log.Errorf("Unexpected frame size %d", n)
		return 0, nil, net.ErrClosed
	}

	// Decode the incoming packet's size from binary.
	size := int(binary.LittleEndian.Uint16(b[:2]))

	n, err = io.ReadFull(c.conn, b[:size])
	if err != nil {
		select {
		case <-c.quit:
			return 0, nil, net.ErrClosed
		default:
			if err == io.EOF {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, err
		}
	}
	if n == 0 || n != size {
		c.log.Errorf("Expected frame size %d, got %d", size, n)
		return 0, nil, net.ErrClosed
	}

	return size, c.remoteAddr, nil
}

func (c *StreamConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	close(c.quit)
	c.conn.Close()
}
