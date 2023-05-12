//go:build !integration
// +build !integration

package vsockconn

import "testing"

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
