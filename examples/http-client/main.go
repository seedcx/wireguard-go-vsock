package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	vsockconn "github.com/balena/wireguard-go-vsock/conn"
)

func main() {
	network := "vsock"
	interfaceName := "wg0"
	localIP, remoteIP := "203.0.113.2", "203.0.113.1"
	tun, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		log.Panic(err)
	}
	realInterfaceName, err := tun.Name()
	if err == nil {
		interfaceName = realInterfaceName
	}
	exec.Command("ip", "address", "add", "dev", interfaceName, localIP, "peer", remoteIP)
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	bind := vsockconn.NewSocketStreamBind(network, logger)
	dev := device.NewDevice(tun, bind, logger)
	err = dev.IpcSet(`private_key=087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379
listen_port=10001
public_key=c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28
allowed_ip=0.0.0.0/0
endpoint=host(2):10000
`)
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}
	exec.Command("ip", "link", "set", "up", "dev", interfaceName)

	client := http.Client{}
	for {
		resp, err := client.Get(fmt.Sprintf("http://%s/", remoteIP))
		if err != nil {
			log.Printf("HTTP Client error: %v", err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Panic(err)
		}
		log.Println(string(body))
	}
}
