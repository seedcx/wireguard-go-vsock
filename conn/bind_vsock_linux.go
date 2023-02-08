//go:build linux
// +build linux

package vsockconn

import "golang.org/x/sys/unix"

const (
	socketFlags = unix.SOCK_CLOEXEC
)
