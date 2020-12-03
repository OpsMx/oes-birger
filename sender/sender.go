package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/skandragon/grpc-bidir/tunnel"
)

var (
	host   = flag.String("host", tunnel.DefaultHostAndPort, "Server and port to connect to")
	target = flag.String("target", "", "The client ID to send the request to")
)

func main() {
	cmdOpts := os.Args[3:]

	flag.Parse()
	if *target == "" {
		log.Fatal("Must specify an -target")
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
	resp, err := client.SendToClient(ctx, &tunnel.CommandRequest{Target: *target, CmdlineArgs: cmdOpts, Stdin: ""})
	if err != nil {
		log.Fatalf("Got error: %v", err)
	}
	//log.Printf("Received: %v", resp)

	fmt.Fprint(os.Stderr, resp.Stderr)
	fmt.Fprint(os.Stdout, resp.Stdout)
	os.Exit(int(resp.ExitCode))
}
