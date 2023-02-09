package vsockconn

import (
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/device"
)

type StreamListener struct {
	l    net.Listener
	quit chan interface{}
	mu   sync.RWMutex
	wg   sync.WaitGroup
	c    *StreamConn
	log  *device.Logger
}

func NewStreamListener(l net.Listener, logger *device.Logger) *StreamListener {
	s := &StreamListener{
		quit: make(chan interface{}),
		l:    l,
		log:  logger,
	}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *StreamListener) Write(b []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return net.ErrClosed
	}
	return s.c.Write(b)
}

func (s *StreamListener) Read(b []byte) (int, net.Addr, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.c == nil {
		return 0, nil, net.ErrClosed
	}
	return s.c.Read(b)
}

func (s *StreamListener) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.c != nil {
		s.c.Close()
	}
	close(s.quit)
	s.l.Close()
	s.wg.Wait()
	s.l = nil
}

func (s *StreamListener) serve() {
	s.log.Verbosef("Routine: listener worker - started")
	defer s.log.Verbosef("Routine: listener worker - stopped")

	defer s.wg.Done()

	for {
		conn, err := s.l.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				s.log.Errorf("Accept error: %w", err)
			}
		} else {
			s.lockedNewConn(conn)
		}
	}
}

func (s *StreamListener) lockedNewConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// It may be the case where the listener is shutting
	// down and the serve() routine just accepted a new
	// socket. In this case, we close the conn.

	if s.l == nil {
		conn.Close()
		return
	}

	if s.c != nil {
		s.c.Close()
	}
	s.c = NewStreamConn(conn, s.log)
}
