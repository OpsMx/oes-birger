# OpsMX API Forwarder

[![Go Report Card](https://goreportcard.com/badge/github.com/opsmx/oes-birger)](https://goreportcard.com/report/github.com/opsmx/oes-birger)

This implements a service where, by running an agent inside a Kubernetes
cluster, API calls can still be sent to it even if the cluster is
behind a firewall.

The purpose of this is to allow reaching into a Kubernetes cluster which is
behind a firewall in a secure, authenticated way.

From the client's (Spinnaker) point of view, it is talking to a standard
Kubernetes endpoint, using a custom certificate authority, user certificate,
and server endpoint.  This endpoint is actually the controller, which uses
the user cert to know which agent to send the API request to.

Streaming (aka, "watch") requests are supported.  Data is sent back from
an API request in a streaming fasion in all cases.  Multiple simulaneous
API calls are supported.

# Components

There are two main compoments:  a "controller" and an "agent".  The controller
runs somewhere a client (such as kubectl) can reach, and the client is pointed
to the controller using a user certificate and a CA cert to authenticate the
controller.  The controller then, based on the server name used in the request,
forwards to a connected agent, which uses its own credentials to connect to a
Kubernetes cluster.

The "agent" connects to a "controller" (which lives outside the firewall,
likely colocated with a CI/CD system such as Spinnaker) which allows access
to the agent's cluster, based on service account and other permissions granted
to the agent.

Running more than one agent with the same name is supported.  If more than
one agent with the same name is connected, they are all sent requests, where
the specific agent is chosen at random.

Currently only one remote cluster is targeted by an agent, although
multiple namespaces can be managed.  The agent itself is very small, and
as it uses a small alpine Linux base image with few additional packages,
has a very small security footprint.

# Prerequisites

`$ go install google.golang.org/protobuf/cmd/protoc-gen-go`

`$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc`

# Building

`$ make`

# Running

Start the controller:
`$ go run controller/controller.go`

Start a agent:
`$ go run agent/agent.go -identity skan1`

# Certificates

There is a binary called `make-ca` which will generate a new certificate authority,
and an initial "control" client key.  These keys and certificates are created in
the Kubernetes secret YAML format.

The CA key and certificate will be used by the controller to generate a
server certificate on startup with all the defined server names it may be using.
It will also use this to generate additional keys for control,
kubernetes API requests, and agents on request.

The certificates issued by the controller's built-in CA have a specific OID which
describes the endpoint type when connecting.  This is required.
