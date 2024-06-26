//go:build !integration
// +build !integration

package vsockconn

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	testListenPortStart = 10000
	testListenPortEnd   = 50000
)

func TestParseVsockAddress(t *testing.T) {
	type test struct {
		input              string
		expectedContextCID uint32
		expectedPort       uint32
		expectedErr        error
	}
	tests := []test{
		// Success cases
		{"vm(3):1234", 3, 1234, nil},
		{"host(2):1234", 2, 1234, nil},
		{"local(1):1234", 1, 1234, nil},
		{"hypervisor(0):1234", 0, 1234, nil},
		{"vm(4294967295):4294967295", 4294967295, 4294967295, nil},
		{":1234", AnyCID, 1234, nil},
		{"vm(3):", 3, AnyPort, nil},
		{":", AnyCID, AnyPort, nil},
		{"0.0.0.1:1234", 1, 1234, nil},
		{"0.0.0.2:4294967295", 2, 4294967295, nil},

		// Failure cases
		{"vm(2):1234", 0, 0, ErrInvalid},
		{"host(3):1234", 0, 0, ErrInvalid},
		{"local(2):1234", 0, 0, ErrInvalid},
		{"hypervisor(1):1234", 0, 0, ErrInvalid},
	}
	for i, test := range tests {
		contextID, port, err := ParseVsockAddress(test.input)
		if test.expectedContextCID != contextID {
			t.Errorf("At %d, expected context ID %d, got %d", i, test.expectedContextCID, contextID)
		}
		if test.expectedPort != port {
			t.Errorf("At %d, expected port %d, got %d", i, test.expectedPort, port)
		}
		if test.expectedErr != err {
			t.Errorf("At %d, expected error %v, got %v", i, test.expectedErr, err)
		}
	}
}

func TestVSOCKBindReceiveFuncAfterClose(t *testing.T) {
	logger := device.NewLogger(device.LogLevelVerbose, "")
	bind := NewBind(logger, WithNetwork("tcp")).(*VSOCKBind)
	port := uint16(testListenPortStart + (testListenPortEnd-testListenPortStart)*rand.Float64())
	fns, _, err := bind.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	for _, fn := range fns {
		// The ReceiveFuncs must not access conn-related fields on VSOCKBind
		// unguarded. Close() nils the conn-related fields resulting in a panic
		// if they violate the mutex.
		fn(bufs, sizes, eps)
	}
}

func TestOpenAndSend(t *testing.T) {
	if raceEnabled {
		t.SkipNow()
	}

	bind1 := NewBind(device.NewLogger(device.LogLevelVerbose, "(b1)"), WithNetwork("tcp"))
	defer bind1.Close()

	port := uint16(testListenPortStart + (testListenPortEnd-testListenPortStart)*rand.Float64())
	receiveFns, _, err := bind1.Open(port)
	if err != nil {
		t.Fatalf("Could not bind to port %d: %v", port, err)
	}

	dst, err := bind1.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Could not parse endpoint 127.0.0.1:%d: %v", port, err)
	}

	bind2 := NewBind(device.NewLogger(device.LogLevelVerbose, "(b2)"), WithNetwork("tcp"))
	defer bind2.Close()

	t.Run("burst initial packets", func(t *testing.T) {
		var expectedPackets [][]byte
		for i := 0; i < 2*maxEnqueuePackets; i++ {
			expectedPackets = append(expectedPackets, produceCountingPackets(int64(i), 10))
		}

		buf := make([][]byte, bind2.BatchSize())
		for i := 0; i < len(expectedPackets); {
			for j := 0; j < bind2.BatchSize() && i+j < len(expectedPackets); j++ {
				buf[j] = expectedPackets[i+j]
			}
			if i+bind2.BatchSize() < len(expectedPackets) {
				i += bind2.BatchSize()
			} else {
				buf = buf[:len(expectedPackets)-i]
				i = len(expectedPackets)
			}
			err = bind2.Send(buf, dst)
			if err != nil {
				t.Fatalf("Error sending data to 127.0.0.1:%d: %v", port, err)
			}
		}

		eps := make([]conn.Endpoint, bind1.BatchSize())
		sizes := make([]int, bind1.BatchSize())
		packets := make([][]byte, bind1.BatchSize())

		var received [][]byte
		for j := 0; j < maxEnqueuePackets; j++ {
			for _, receiveFn := range receiveFns {
				for i := range packets {
					packets[i] = make([]byte, maxPacketSize)
				}
				n, err := receiveFn(packets, sizes, eps)
				if n != bind1.BatchSize() {
					t.Fatalf("Required n = %d, got %d", bind1.BatchSize(), n)
				}
				if err != nil {
					t.Fatalf("Required no error, got %v", err)
				}
				for i := 0; i < n; i++ {
					received = append(received, packets[i][:sizes[i]])
				}
			}
		}

		if len(received) != maxEnqueuePackets {
			t.Fatalf("Required %d received packet, got %d", maxEnqueuePackets, len(received))
		}
		if !bytes.Equal(received[0], expectedPackets[len(expectedPackets)-maxEnqueuePackets]) {
			t.Fatalf("Expected to receive %v, got %v", expectedPackets[len(expectedPackets)-maxEnqueuePackets], received[0])
		}
	})

	time.Sleep(time.Second)

	t.Run("next packets after connecting", func(t *testing.T) {
		var expectedPackets [][]byte
		for i := 0; i < 100; i++ {
			expectedPackets = append(expectedPackets, produceCountingPackets(int64(i), 10))
		}

		buf := make([][]byte, bind2.BatchSize())
		for i := 0; i < len(expectedPackets); {
			for j := 0; j < bind2.BatchSize() && i+j < len(expectedPackets); j++ {
				buf[j] = expectedPackets[i+j]
			}
			if i+bind2.BatchSize() < len(expectedPackets) {
				i += bind2.BatchSize()
			} else {
				buf = buf[:len(expectedPackets)-i]
				i = len(expectedPackets)
			}
			err = bind2.Send(buf, dst)
			if err != nil {
				t.Fatalf("Error sending data to 127.0.0.1:%d: %v", port, err)
			}
		}

		eps := make([]conn.Endpoint, bind1.BatchSize())
		sizes := make([]int, bind1.BatchSize())
		packets := make([][]byte, bind1.BatchSize())

		var received [][]byte
		for j := 0; j < 100; j++ {
			for _, receiveFn := range receiveFns {
				for i := range packets {
					packets[i] = make([]byte, maxPacketSize)
				}
				n, err := receiveFn(packets, sizes, eps)
				if n != bind1.BatchSize() {
					t.Fatalf("Required n = %d, got %d", bind1.BatchSize(), n)
				}
				if err != nil {
					t.Fatalf("Required no error, got %v", err)
				}
				for i := 0; i < n; i++ {
					received = append(received, packets[i][:sizes[i]])
				}
			}
		}

		if len(received) != 100 {
			t.Fatalf("Required 100 received packet, got %d", len(received))
		}
		if !bytes.Equal(received[0], expectedPackets[0]) {
			t.Fatalf("Expected to receive %v, got %v", expectedPackets[0], received[0])
		}
	})
}

func produceCountingPackets(i int64, size int) []byte {
	bi := new(big.Int).SetInt64(i)
	return bi.FillBytes(make([]byte, size))
}
