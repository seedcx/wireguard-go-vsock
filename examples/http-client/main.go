package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/seedcx/wireguard-go-vsock/vsockconn"
)

const retryInterval = 5 * time.Second

func main() {
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
	cmd := exec.Command("ip", "address", "add", "dev", interfaceName, localIP, "peer", remoteIP)
	if err := cmd.Run(); err != nil {
		log.Panic(err)
	}
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	bind := vsockconn.NewBind(logger)
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
	cmd = exec.Command("ip", "link", "set", "up", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		log.Panic(err)
	}

	client := http.Client{}
	for {
		resp, err := client.Get(fmt.Sprintf("http://%s/", remoteIP))
		if err != nil {
			log.Printf("HTTP Client error %v, retrying in %s", err, retryInterval)
			time.Sleep(retryInterval)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Panic(err)
		}
		log.Println(string(body))
		time.Sleep(retryInterval)
	}
}
