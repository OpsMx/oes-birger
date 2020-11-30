package main

import (
	"flag"
	"io"
	"log"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"

	"github.com/skandragon/grpc-bidir/tunnel"
)

var (
	host     = flag.String("host", "localhost:9000", "Server and port to connect to")
	tickTime = flag.Int("tickTime", 30, "Time between sending Ping messages")
	identity = flag.String("identity", "", "The client ID to send to the server")
)

func runTunnel(client tunnel.TunnelServiceClient, ticker chan uint64, identity string) {
	ctx := context.Background()
	stream, err := client.EventTunnel(ctx)
	if err != nil {
		log.Fatalf("%v.SayHello(_) = _, %v", client, err)
	}

	// Sign in
	req := &tunnel.EventWrapper{
		Event: &tunnel.EventWrapper_SigninRequest{
			SigninRequest: &tunnel.SigninRequest{Identity: identity, StartTime: tunnel.Now()},
		},
	}
	log.Printf("Sending: %v", req)
	if err = stream.Send(req); err != nil {
		log.Fatalf("Unable to send a SigninRequest: %v", err)
	}

	// Handle periodic pings from the ticker.
	go func() {
		for {
			ts := <-ticker
			req := &tunnel.EventWrapper{
				Event: &tunnel.EventWrapper_PingRequest{
					PingRequest: &tunnel.PingRequest{Ts: ts},
				},
			}
			log.Printf("Sending %v", req)
			if err = stream.Send(req); err != nil {
				log.Fatalf("Unable to send a PingRequest: %v", err)
			}
		}
	}()

	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				// Server has closed the connection.
				close(waitc)
				return
			}
			if err != nil {
				log.Fatalf("Failed to receive a message: %T: %v", err, err)
			}
			switch x := in.Event.(type) {
			case *tunnel.EventWrapper_PingResponse:
				req := in.GetPingResponse()
				log.Printf("Received: PingResponse: %v", req)
			case *tunnel.EventWrapper_SigninResponse:
				req := in.GetSigninResponse()
				log.Printf("Succesfully signed in: %v", req)
			case *tunnel.EventWrapper_CommandRequest:
				req := in.GetCommandRequest()
				resp := &tunnel.EventWrapper{
					Event: &tunnel.EventWrapper_CommandResponse{
						CommandResponse: &tunnel.CommandResponse{Id: req.Id, Body: "From the client!"},
					},
				}
				log.Printf("Sending %v", resp)
				if err = stream.Send(resp); err != nil {
					log.Fatalf("Unable to send: %v", err)
				}
			case nil:
				// ignore for now
			default:
				log.Printf("Received unknown message: %T: %v", x, in)
			}
		}
	}()
	<-waitc
	stream.CloseSend()
}

func runTicker(tickTime int, ticker chan uint64) {
	log.Printf("Starting ticker to send pings every %d seconds.", tickTime)
	go func() {
		for {
			time.Sleep(time.Duration(tickTime) * time.Second)
			ticker <- tunnel.Now()
		}
	}()

}

func main() {
	flag.Parse()
	if *identity == "" {
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

	ticker := make(chan uint64)
	runTicker(*tickTime, ticker)

	log.Printf("Starting tunnel.")
	runTunnel(client, ticker, *identity)
	log.Printf("Done.")
}
