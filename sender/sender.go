package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	"github.com/skandragon/grpc-bidir/tunnel"
)

var (
	host   = flag.String("host", "localhost:9000", "Server and port to connect to")
	target = flag.String("target", "", "The client ID to send the request to")
)

func main() {
	flag.Parse()
	if *target == "" {
		log.Fatal("Must specify an -identity")
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.Dial(*host, opts...)
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	defer conn.Close()

	client := tunnel.NewTunnelServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.SendToClient(ctx, &tunnel.Message{Target: *target, Body: "testing"})
	if err != nil {
		log.Fatalf("Got error: %v", err)
	}
	log.Printf("Received: %v", resp)
}
