# grpc-bidir

This sample implements a bi-directional event stream using GRPC.

There are two main compoments:  a "controller" and an "agent".  The controller
runs somewhere a client (such as kubectl) can reach, and the client is pointed
to the controller using a user certificate and a CA cert to authenticate the
controller.  The controller then, based on the server name used in the request,
forwards to a connected agent, which uses its own credentials to connect to a
Kubernetes cluster.

The purpose of this is to allow reaching into a Kubernetes cluster which is
behind a firewall in a secure, authenticated way.

Currently only one remote context is allowed, but in theory we could map the
user coming in to a different kubernetes context in the agent.  This would
also work by having different contexts and agents per user, but would be messy.

As a warning, this is my first attempt at any Go code...

# Prerequisites

`go get -u github.com/golang/protobuf/{proto,protoc-gen-go}`

`go get -u google.golang.org/grpc`

# Building

`protoc --go_out=plugins=grpc:tunnel tunnel/tunnel.proto`

# Running

Start the controller:
`go run controller/controller.go`

Start a agent:
`go run agent/agent.go -identity skan1`

# Todo

* Implement chunked transfer encoding, so we can support "watch"
