package vsockconn

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/device"
)

const (
	maxMTU              = 1500
	ethernetMinimumSize = 64
)

type Datagram struct {
	Packet     []byte
	RemoteAddr net.Addr
}

type StreamConn struct {
	conn     net.Conn
	quit     chan interface{}
	wg       sync.WaitGroup
	log      *device.Logger
	received chan<- Datagram
}

func NewStreamConn(conn net.Conn, received chan<- Datagram, logger *device.Logger) *StreamConn {
	c := &StreamConn{
		quit:     make(chan interface{}),
		conn:     conn,
		log:      logger,
		received: received,
	}
	c.wg.Add(1)
	go func() {
		c.receive()
		c.wg.Done()
	}()
	return c
}

func (c *StreamConn) Write(b []byte) error {
	err := binary.Write(c.conn, binary.LittleEndian, uint16(len(b)))
	if err != nil {
		return err
	}

	for len(b) > 0 {
		n, err := c.conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}

	return nil
}

func (c *StreamConn) Close() {
	close(c.quit)
	c.conn.Close()
	c.wg.Wait()
}

func (c *StreamConn) receive() {
	c.log.Verbosef("Routine: connection worker - started")
	defer c.log.Verbosef("Routine: connection worker - stopped")

	defer c.conn.Close()

	packetSize := make([]byte, 2)
	packet := make([]byte, maxMTU+ethernetMinimumSize)

	for {
		// Read the incoming packet's size as a binary value.
		n, err := io.ReadFull(c.conn, packetSize)
		if err != nil {
			select {
			case <-c.quit:
				return
			default:
				if err == io.EOF {
					return
				}
				c.log.Errorf("Error reading frame size: %w", err)
				return
			}
		}
		if n != 2 {
			c.log.Errorf("Unexpected frame size %d", n)
			return
		}

		// Decode the incoming packet's size from binary.
		size := int(binary.LittleEndian.Uint16(packetSize))

		n, err = io.ReadFull(c.conn, packet[:size])
		if err != nil {
			select {
			case <-c.quit:
				return
			default:
				c.log.Errorf("Error reading frame: %w", err)
				return
			}
		}
		if n == 0 || n != size {
			c.log.Errorf("Expected frame size %d, got %d", size, n)
			return
		}

		c.received <- Datagram{packet[:size], c.conn.RemoteAddr()}
	}
}
