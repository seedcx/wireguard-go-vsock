package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	vsockconn "github.com/balena/wireguard-go-vsock/conn"
)

func main() {
	network := "vsock"
	interfaceName := "wg0"
	tun, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		log.Panic(err)
	}
	realInterfaceName, err := tun.Name()
	if err == nil {
		interfaceName = realInterfaceName
	}
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	bind := vsockconn.NewSocketStreamBind(network, logger)
	dev := device.NewDevice(tun, bind, logger)
	dev.IpcSet(`private_key=003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641
listen_port=10000
public_key=f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c
allowed_ip=0.0.0.0/0
endpoint=vm(6):10001
`)
	dev.Up()
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("> %s - %s - %s", request.RemoteAddr, request.URL.String(), request.UserAgent())
		io.WriteString(writer, "Hello from userspace TCP!")
	})
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Panicln(err)
	}
}
