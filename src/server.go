package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
)

const defaultNetPort = 53

type IDnsServer interface {
	Listen(ctx context.Context)
}

type UdpDnsServer struct {
	engine IDnsEngine
	port   int32

	connection net.PacketConn
}

func (server *UdpDnsServer) createSocket() error {
	var err error

	server.connection, err = net.ListenPacket("udp", ":53")
	if err != nil {
		return errors.New(FailedToCreateSocket)
	}

	return nil
}

func (server *UdpDnsServer) Listen(ctx context.Context) {
	go func(ctx context.Context) {
		buf := make([]byte, 1024)

		for {
			n, addr, err := server.connection.ReadFrom(buf)
			fmt.Println("Message from", addr)
			if err != nil {
				continue
			}

			responseBuf, responseLength, err := server.engine.HandleMessage(buf, n)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}

			server.connection.WriteTo(responseBuf[:responseLength], addr)

			fmt.Println("Message sent to", addr)

			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}(ctx)
}

func CreateUdpDnsServer(engine IDnsEngine, port int32) (*UdpDnsServer, error) {
	var server = &UdpDnsServer{engine, port, nil}

	if engine == nil {
		return server, errors.New(DnsEngineRequired)
	}

	if port == 0 {
		port = defaultNetPort
	}

	err := server.createSocket()
	if err != nil {
		return server, err
	}

	runtime.SetFinalizer(server, func(s *UdpDnsServer) {
		s.connection.Close()
	})

	return server, nil
}
