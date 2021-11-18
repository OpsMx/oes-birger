# OpsMX API and Command Forwarder

[![Go Report Card](https://goreportcard.com/badge/github.com/opsmx/oes-birger)](https://goreportcard.com/report/github.com/opsmx/oes-birger)

This implements a service where, by running an agent inside a Kubernetes
cluster, remote commands can still be sent to it even if the cluster is
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
as it does not currently use a Linux distribution, has a very small
security footprint.

As a warning, this is my first attempt at any Go code...

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
