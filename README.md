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

# Certificates

There is a binary called `make-ca` which will generate a new certificate authority,
and an initial "control" client key.  These keys and certificates are created in
the Kubernetes secret YAML format.

The CA key and certificate will be used by the controller to generate a
server certificate on startup with all the defined server names it may be using.
It will also use this to generate additional keys for control, command-requests,
kubernetes API requests, and agents on request.

## Certificate Names

The server certificate is a standard server cert, which will be used by the
usual Go libraries to verify that the server is presenting an identity
that matches the URL being used to contact it.

For agent, command, remote-command, and agent certificates, the CommonName is
treated specially.  The format is "agentName.type" where "agentName" is used to
match incoming Kubernetes API requests and remote-command requests to a connected
agent, by name.  That is, if an agent connects with a certificate named "foo.agent",
then a certificate called "foo.remote-command" or "foo.client" can connect and send
it Kubernets API requests or remote-command requests.
