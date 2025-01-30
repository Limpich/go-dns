package main

import (
	"context"
	"fmt"
	"time"
)

func main() {
	engine := &DnsEngine{}
	server, err := CreateUdpDnsServer(engine, 0)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Server created")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		server.Listen(ctx)
		fmt.Println("Server listening on :53")
	}()

	time.Sleep(1 * time.Minute)
	cancel()
}
