package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	vsockconn "github.com/balena/wireguard-go-vsock/conn"
)

func main() {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("203.0.113.2")},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		log.Panic(err)
	}
	interfaceName, _ := tun.Name()
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	dev := device.NewDevice(tun, vsockconn.NewSocketStreamBind("tcp", logger), logger)
	err = dev.IpcSet(`private_key=087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379
listen_port=10001
public_key=c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28
allowed_ip=0.0.0.0/0
endpoint=127.0.0.1:10000
`)
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}
	resp, err := client.Get("http://203.0.113.1/")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))
}
