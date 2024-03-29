//go:build !integration
// +build !integration

package vsockconn

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	var buf bytes.Buffer
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// publicKey derives the corresponding public key from the private key.
func publicKey(sk device.NoisePrivateKey) (pk device.NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(&sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB) (cfgs, endpointCfgs [2]string, sks [2]device.NoisePrivateKey, pks [2]device.NoisePublicKey) {
	_, err := io.ReadFull(rand.Reader, sks[0][:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	_, err = io.ReadFull(rand.Reader, sks[1][:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	pks[0], pks[1] = publicKey(sks[0]), publicKey(sks[1])

	cfgs[0] = uapiCfg(
		"private_key", hex.EncodeToString(sks[0][:]),
		"listen_port", "%d",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pks[1][:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
	)
	endpointCfgs[0] = uapiCfg(
		"public_key", hex.EncodeToString(pks[1][:]),
		"endpoint", "127.0.0.1:%d",
	)
	cfgs[1] = uapiCfg(
		"private_key", hex.EncodeToString(sks[1][:]),
		"listen_port", "%d",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pks[0][:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
	)
	endpointCfgs[1] = uapiCfg(
		"public_key", hex.EncodeToString(pks[0][:]),
		"endpoint", "127.0.0.1:%d",
	)
	return
}

// A testPair is a pair of testPeers.
type testPair [2]testPeer

// A testPeer is a peer used for testing.
type testPeer struct {
	tun *tuntest.ChannelTUN
	dev *device.Device
	ip  netip.Addr
	sk  device.NoisePrivateKey
	pk  device.NoisePublicKey
}

type SendDirection bool

const (
	Ping SendDirection = true
	Pong SendDirection = false
)

func (d SendDirection) String() string {
	if d == Ping {
		return "ping"
	}
	return "pong"
}

func (pair *testPair) Send(tb testing.TB, ping SendDirection, done chan struct{}) {
	tb.Helper()
	p0, p1 := pair[0], pair[1]
	if !ping {
		// pong is the new ping
		p0, p1 = p1, p0
	}
	msg := tuntest.Ping(p0.ip, p1.ip)
	p1.tun.Outbound <- msg
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var err error
	select {
	case msgRecv := <-p0.tun.Inbound:
		if !bytes.Equal(msg, msgRecv) {
			err = fmt.Errorf("%s did not transit correctly", ping)
		}
	case <-timer.C:
		err = fmt.Errorf("%s did not transit", ping)
	case <-done:
	}
	if err != nil {
		// The error may have occurred because the test is done.
		select {
		case <-done:
			return
		default:
		}
		// Real error.
		tb.Error(err)
	}
}

// genTestPair creates a testPair.
func genTestPair(tb testing.TB, network string) (pair testPair) {
	var loggers []*device.Logger
	for i := range pair {
		level := device.LogLevelVerbose
		if _, ok := tb.(*testing.B); ok && !testing.Verbose() {
			level = device.LogLevelError
		}
		loggers = append(loggers, device.NewLogger(level, fmt.Sprintf("dev%d: ", i)))
	}
	var ports [2]uint16
	ports[0] = uint16(testListenPortStart + (testListenPortEnd-testListenPortStart)*mathrand.Float64())
	ports[1] = uint16(testListenPortStart + (testListenPortEnd-testListenPortStart)*mathrand.Float64())
	cfg, endpointCfg, sks, pks := genConfigs(tb)
	var binds [2]conn.Bind
	binds[0], binds[1] = NewBind(loggers[0], WithNetwork(network)), NewBind(loggers[1], WithNetwork(network))
	// Bring up a ChannelTun for each config.
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.sk = sks[i]
		p.pk = pks[i]
		level := device.LogLevelVerbose
		if _, ok := tb.(*testing.B); ok && !testing.Verbose() {
			level = device.LogLevelError
		}
		p.dev = device.NewDevice(p.tun.TUN(), binds[i], device.NewLogger(level, fmt.Sprintf("dev%d: ", i)))
		cfg[i] = fmt.Sprintf(cfg[i], ports[i])
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Errorf("failed to configure device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		if err := p.dev.Up(); err != nil {
			tb.Errorf("failed to bring up device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], ports[i])
	}
	for i := range pair {
		p := &pair[i]
		if err := p.dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Errorf("failed to configure device endpoint %d: %v", i, err)
			p.dev.Close()
			continue
		}
		// The device is ready. Close it when the test completes.
		tb.Cleanup(p.dev.Close)
	}
	return
}

func TestTwoDevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, "tcp")
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

func TestUpDown(t *testing.T) {
	goroutineLeakCheck(t)
	const itrials = 50
	const otrials = 10

	for n := 0; n < otrials; n++ {
		pair := genTestPair(t, "tcp")
		for i := range pair {
			uapiConf := fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=1\n",
				hex.EncodeToString(pair[i^1].pk[:]))
			pair[i].dev.IpcSet(uapiConf)
		}
		var wg sync.WaitGroup
		wg.Add(len(pair))
		for i := range pair {
			go func(d *device.Device) {
				defer wg.Done()
				for i := 0; i < itrials; i++ {
					if err := d.Up(); err != nil {
						t.Errorf("failed up bring up device: %v", err)
					}
					time.Sleep(time.Duration(mathrand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
					if err := d.Down(); err != nil {
						t.Errorf("failed to bring down device: %v", err)
					}
					time.Sleep(time.Duration(mathrand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
				}
			}(pair[i].dev)
		}
		wg.Wait()
		for i := range pair {
			pair[i].dev.Up()
			pair[i].dev.Close()
		}
	}
}

// TestConcurrencySafety does other things concurrently with tunnel use.
// It is intended to be used with the race detector to catch data races.
func TestConcurrencySafety(t *testing.T) {
	pair := genTestPair(t, "tcp")
	done := make(chan struct{})

	const warmupIters = 1000
	var warmup sync.WaitGroup
	warmup.Add(warmupIters)
	go func() {
		// Send data continuously back and forth until we're done.
		// Note that we may continue to attempt to send data
		// even after done is closed.
		i := warmupIters
		for ping := Ping; ; ping = !ping {
			pair.Send(t, ping, done)
			select {
			case <-done:
				return
			default:
			}
			if i > 0 {
				warmup.Done()
				i--
			}
		}
	}()
	warmup.Wait()

	applyCfg := func(cfg string) {
		err := pair[0].dev.IpcSet(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Change persistent_keepalive_interval concurrently with tunnel use.
	t.Run("persistentKeepaliveInterval", func(t *testing.T) {
		pub := pair[1].pk
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(pub[:]),
			"persistent_keepalive_interval", "1",
		)
		for i := 0; i < 1000; i++ {
			applyCfg(cfg)
		}
	})

	// Change private keys concurrently with tunnel use.
	t.Run("privateKey", func(t *testing.T) {
		bad := uapiCfg("private_key", "7777777777777777777777777777777777777777777777777777777777777777")
		good := uapiCfg("private_key", hex.EncodeToString(pair[0].sk[:]))
		// Set iters to a large number like 1000 to flush out data races quickly.
		// Don't leave it large. That can cause logical races
		// in which the handshake is interleaved with key changes
		// such that the private key appears to be unchanging but
		// other state gets reset, which can cause handshake failures like
		// "Received packet with invalid mac1".
		const iters = 1
		for i := 0; i < iters; i++ {
			applyCfg(bad)
			applyCfg(good)
		}
	})

	// Perform bind updates and keepalive sends concurrently with tunnel use.
	t.Run("bindUpdate and keepalive", func(t *testing.T) {
		const iters = 10
		for i := 0; i < iters; i++ {
			for _, peer := range pair {
				peer.dev.BindUpdate()
				peer.dev.SendKeepalivesToPeersWithCurrentKeypair()
			}
		}
	})

	close(done)
}

func TestHighThroughputTransfer(t *testing.T) {
	pair := genTestPair(t, "tcp")
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	var packets [][]byte
	for i := 0; i < 10000; i++ {
		msg := produceCountingPackets(int64(i), 1024)
		packet, err := buildUDPPacket(pair[1].ip, pair[0].ip, 1339, 1338, msg)
		if err != nil {
			t.Fatalf("Error creating UDP packet #%d: %v", i, err)
		}
		packets = append(packets, packet)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < len(packets); i++ {
			pair[0].tun.Outbound <- packets[i]
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < len(packets); i++ {
			p := <-pair[1].tun.Inbound
			if !bytes.Equal(packets[i], p) {
				t.Errorf("Packet #%d didn't match, wanted %v, got %v", i, packets[i], p)
			}
		}
	}()

	wg.Wait()

	for i := range pair {
		pair[i].dev.Close()
	}
}

func BenchmarkLatency(b *testing.B) {
	pair := genTestPair(b, "tcp")

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair.Send(b, Ping, nil)
		pair.Send(b, Pong, nil)
	}
}

func BenchmarkThroughput(b *testing.B) {
	pair := genTestPair(b, "tcp")

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	// Measure how long it takes to receive b.N packets,
	// starting when we receive the first packet.
	var recv atomic.Uint64
	var elapsed time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var start time.Time
		for {
			<-pair[0].tun.Inbound
			new := recv.Add(1)
			if new == 1 {
				start = time.Now()
			}
			// Careful! Don't change this to else if; b.N can be equal to 1.
			if new == uint64(b.N) {
				elapsed = time.Since(start)
				return
			}
		}
	}()

	// Send packets as fast as we can until we've received enough.
	ping := tuntest.Ping(pair[0].ip, pair[1].ip)
	pingc := pair[1].tun.Outbound
	var sent uint64
	for recv.Load() != uint64(b.N) {
		sent++
		pingc <- ping
	}
	wg.Wait()

	b.ReportMetric(float64(elapsed)/float64(b.N), "ns/op")
	b.ReportMetric(1-float64(b.N)/float64(sent), "packet-loss")
}

func FuzzUDPSend(f *testing.F) {
	pair := genTestPair(f, "tcp")
	pair.Send(f, Ping, nil)
	pair.Send(f, Pong, nil)

	f.Add(1, []byte{1})
	f.Fuzz(func(t *testing.T, i int, msg []byte) {
		i &= 1
		packet, err := buildUDPPacket(pair[i^1].ip, pair[i].ip, 1339, 1338, msg)
		if err != nil {
			t.Fatalf("Error building UDP packet: %v", err)
		}
		pair[i].tun.Outbound <- packet
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		err = nil
		select {
		case msgRecv := <-pair[i^1].tun.Inbound:
			if !bytes.Equal(packet, msgRecv) {
				err = fmt.Errorf("%s did not transit correctly", hex.EncodeToString(msg))
			}
		case <-timer.C:
			err = fmt.Errorf("%s did not transit", hex.EncodeToString(msg))
		}
		if err != nil {
			t.Error(err)
		}
	})

	for i := range pair {
		pair[i].dev.Close()
	}
}

func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for i := 0; i < 10000; i++ {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}

func buildUDPPacket(dst, src netip.Addr, dstPort, srcPort int, payload []byte) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{
		DstIP:    dst.AsSlice(),
		SrcIP:    src.AsSlice(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("Failed calc checksum: %s", err)
	}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("Failed serialize packet: %s", err)
	}
	return buffer.Bytes(), nil
}
