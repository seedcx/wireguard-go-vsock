//go:build integration
// +build integration

package vsockconn

import (
	"fmt"
	"os/exec"
	"runtime"
	"testing"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const configTemplate = `private_key=%s
listen_port=%d
public_key=%s
allowed_ip=0.0.0.0/0
endpoint=127.0.0.1:%d
`

type peer struct {
	iface      string
	bind       *VSOCKBind
	dev        *device.Device
	tun        tun.Device
	ip         string
	pk         string
	pvk        string
	listenPort int
	cfg        string
	peer       *device.Peer
	logger     *device.Logger
}

func createConnectedPeers(t *testing.T) (*peer, *peer) {
	peers := [2]*peer{
		{
			ip:         "203.0.113.1",
			pk:         "f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c",
			pvk:        "087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379",
			listenPort: 10000,
		},
		{
			ip:         "203.0.113.2",
			pk:         "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28",
			pvk:        "003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641",
			listenPort: 10001,
		},
	}

	switch runtime.GOOS {
	case "darwin":
		peers[0].iface, peers[1].iface = "utun42", "utun43"
	case "linux":
		peers[0].iface, peers[1].iface = "wg42", "wg43"
	default:
		t.Fatal("Unsupported OS")
	}

	for i, p := range peers {
		endpointPort, peerPk := peers[(i+1)%2].listenPort, peers[(i+1)%2].pk
		p.cfg = fmt.Sprintf(configTemplate, p.pvk, p.listenPort, peerPk, endpointPort)
	}

	var err error
	for i, p := range peers {
		p.tun, err = tun.CreateTUN(p.iface, device.DefaultMTU)
		if err != nil {
			t.Fatalf("Error opening TUN interface %q: %v", p.iface, err)
		}

		realInterfaceName, err := p.tun.Name()
		if err == nil {
			p.iface = realInterfaceName
		}

		localIP, remoteIP := p.ip, peers[(i+1)%2].ip
		cmd := exec.Command("ip", "address", "add", "dev", p.iface, localIP, "peer", fmt.Sprintf("%s/30", remoteIP))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error assigning ip %q to interface %q: %v", p.ip, p.iface, err)
		}

		p.logger = device.NewLogger(
			device.LogLevelVerbose,
			fmt.Sprintf("(%s) ", p.iface),
		)

		p.bind = NewBind(p.logger, WithNetwork("tcp")).(*VSOCKBind)
		p.dev = device.NewDevice(p.tun, p.bind, p.logger)
		p.dev.IpcSet(p.cfg)
		p.dev.Up()

		cmd = exec.Command("ip", "link", "set", "up", "dev", p.iface)
		if err := cmd.Run(); err != nil {
			t.Fatalf("Error bringing interface %q up: %v", p.iface, err)
		}
	}

	return peers[0], peers[1]
}

func shutdownPeer(t *testing.T, p *peer) {
	p.logger.Verbosef("Shutting down %q...", p.iface)
	p.dev.Close()

	if p.bind.l != nil {
		t.Error("Close didn't close the listening socket")
	}
	if p.bind.l != nil {
		t.Error("Close left pending packets in the queue")
	}
	if len(p.bind.conns) > 0 {
		t.Error("Pending connections after closing")
	}

	p.logger.Verbosef("Closing TUN %q...", p.iface)
	p.tun.Close()

	cmd := exec.Command("ip", "link", "set", "down", "dev", p.iface)
	cmd.Run()
}

func TestTearUpShutdown(t *testing.T) {
	// Notice the below test does not work because there are two link layers
	// being created. As packets are routed from different link layers, they
	// don't reach each other, and thus ping times out.
	//
	// However, there are pings being executed from the two ends, so it serves to
	// test the stack.

	p1, p2 := createConnectedPeers(t)

	p1.logger.Verbosef("Finished creating peers")

	defer shutdownPeer(t, p1)
	defer shutdownPeer(t, p2)

	out, _ := exec.Command("netstat", "-tupan").Output()
	p1.logger.Verbosef("netstat -tupan:\n%s", out)

	out, _ = exec.Command("route", "-n").Output()
	p1.logger.Verbosef("route -n:\n%s", out)

	out, _ = exec.Command("ip", "a").Output()
	p1.logger.Verbosef("ip a:\n%s", out)

	p1.logger.Verbosef("ping -n 10 -c 1 -W 1 -I %s %s", p1.iface, p2.ip)
	out, _ = exec.Command("ping", "-n", "10", "-c", "1", "-W", "1", "-I", p1.iface, p2.ip).Output()
	p1.logger.Verbosef("\n%s", out)

	p2.logger.Verbosef("ping -n 10 -c 1 -W 1 -I %s %s", p2.iface, p1.ip)
	out, _ = exec.Command("ping", "-n", "10", "-c", "1", "-W", "1", "-I", p2.iface, p1.ip).Output()
	p2.logger.Verbosef("\n%s", out)
}
