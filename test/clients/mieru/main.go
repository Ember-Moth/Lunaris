// SPDX-License-Identifier: GPL-3.0-only
// Standalone interoperability client; the node does not depend on the Mieru app.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	client "github.com/enfein/mieru/v3/apis/client"
	common "github.com/enfein/mieru/v3/apis/common"
	model "github.com/enfein/mieru/v3/apis/model"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type config struct {
	Server, Transport, Username, Password, TCPTarget, UDPTarget string
	Connections                                                 int
}

func main() {
	path := flag.String("config", "", "test configuration")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		panic(err)
	}
	var cfg config
	if err = json.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}
	if err = run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func target(raw, network string) (model.NetAddrSpec, error) {
	host, p, err := net.SplitHostPort(raw)
	if err != nil {
		return model.NetAddrSpec{}, err
	}
	port, err := strconv.Atoi(p)
	return model.NetAddrSpec{Net: network, AddrSpec: model.AddrSpec{IP: net.ParseIP(host), Port: port}}, err
}
func run(c config) error {
	host, p, err := net.SplitHostPort(c.Server)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return err
	}
	transport := pb.TransportProtocol_TCP
	if c.Transport == "udp" {
		transport = pb.TransportProtocol_UDP
	}
	proxy := client.NewClient()
	if err = proxy.Store(&client.ClientConfig{Profile: &pb.ClientProfile{ProfileName: proto.String("loopback"), User: &pb.User{Name: proto.String(c.Username), Password: proto.String(c.Password)}, Multiplexing: &pb.MultiplexingConfig{Level: pb.MultiplexingLevel_MULTIPLEXING_HIGH.Enum()}, Servers: []*pb.ServerEndpoint{{IpAddress: proto.String(host), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: transport.Enum()}}}}}}); err != nil {
		return err
	}
	if err = proxy.Start(); err != nil {
		return err
	}
	defer proxy.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tcp, err := target(c.TCPTarget, "tcp")
	if err != nil {
		return err
	}
	count := max(1, c.Connections)
	results := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := proxy.DialContext(ctx, tcp)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			payload := bytes.Repeat([]byte("mieru-independent-client"), 4096)
			if _, err = conn.Write(payload); err == nil {
				out := make([]byte, len(payload))
				_, err = io.ReadFull(conn, out)
				if err == nil && !bytes.Equal(out, payload) {
					err = fmt.Errorf("TCP payload mismatch")
				}
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err = range results {
		if err != nil {
			return err
		}
	}
	udp, err := target(c.UDPTarget, "udp")
	if err != nil {
		return err
	}
	conn, err := proxy.DialContext(ctx, udp)
	if err != nil {
		return err
	}
	packet := common.NewUDPAssociateWrapper(common.NewPacketOverStreamTunnel(conn))
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(10 * time.Second))
	address, err := net.ResolveUDPAddr("udp", c.UDPTarget)
	if err != nil {
		return err
	}
	payload := bytes.Repeat([]byte("mieru-udp"), 300)
	if _, err = packet.WriteTo(payload, address); err != nil {
		return err
	}
	out := make([]byte, 65535)
	n, _, err := packet.ReadFrom(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, out[:n]) {
		return fmt.Errorf("UDP payload mismatch")
	}
	fmt.Printf("PASS Mieru %s: %d TCP streams + UDP\n", c.Transport, count)
	return nil
}
