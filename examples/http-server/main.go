package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	vsockconn "github.com/balena/wireguard-go-vsock/conn"
)

func main() {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, vsockconn.NewVsockSocketBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(`private_key=a8dac1d8a70a751f0f699fb14ba1cff7b79cf4fbd8f09f44c6e6a90d0369604f
public_key=25123c5dcd3328ff645e4f2a3fce0d754400d3887a0cb7c56f0267e20fbf3c5b
listen_port=10000
allowed_ip=0.0.0.0/0
persistent_keepalive_interval=25
`)
	dev.Up()
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Panicln(err)
	}
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("> %s - %s - %s", request.RemoteAddr, request.URL.String(), request.UserAgent())
		io.WriteString(writer, "Hello from userspace TCP!")
	})
	err = http.Serve(listener, nil)
	if err != nil {
		log.Panicln(err)
	}
}
