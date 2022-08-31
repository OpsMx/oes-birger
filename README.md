# OpsMX API Forwarder

[![Go Report Card](https://goreportcard.com/badge/github.com/opsmx/oes-birger)](https://goreportcard.com/report/github.com/opsmx/oes-birger)

# Generic HTTP proxy

This is a slightly protocol aware HTTP proxy, which securely crosses
security domains.  The primary use case is for a SaaS install of some
central software which needs to reach into a customer's cloud in some
secure way.  VPNs could be used, which requires out of band configuration
and likely more complexity and teams.

Birger allows an agent to be run in a Kubernetes cluster, configured
with security tokens for various services.  Access to these services
are provided to the controller, which can be contacted in a secure
way to access the agent-provided services.

The credentials used by the agent to contact services (kubernetes, jenkins,
etc) are never provided to the controller.  This allows secure, customer
regulated access to internal services and changing credentials as needed.

## Using the Services

The controller has a HTTPS port open which accepts service requests.
These may be a controller-CA provided certificate, or a controller-provided
JWT token in an `Authentication` header.  For Kubernetes, certificates
are used, while for other HTTP-based services, the Bearer or Basic auth method
and the JWT token should be used.

# Kubernetes Service

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

See the examples in the `examples/local-deploy` directory.

# Certificates

There is a binary called `make-ca` which will generate a new certificate authority,
and an initial "control" client key.  These keys and certificates are created in
the Kubernetes secret YAML format.

The CA key and certificate will be used by the controller to generate a
server certificate on startup with all the defined server names it may be using.
It will also use this to generate additional keys for control,
kubernetes API requests, and agents on request.

The certificates issued by the controller's built-in CA have a specific tag which
describes the endpoint type when connecting.  This is required.

# Service Registry

| Service Type | Support Level | Location | Description |
| --- | --- | --- | --- |
| aws | Partial | Agent | AWS API |
| clouddriver | Full | Agent | Spinnaker Cloud Driver API.  Special handling of the HTTP messages. |
| front50 | Full | Controller | Spinnaker Front50 API.  Special handling of the HTTP messages. |
| fiat | Full | Controller | Spinnaker Fiat API. Special handling of the HTTP messages. |
| jenkins | Full | Either | Jenkins CI API |
| kuberetes | Full | Agent | Kubernetes API endpoint |

Types not listed here should not be used.  Local or custom types (without any special handling needed, just usual HTTP protocol proxy) can be named with a `x-` prefix, such as `x-my-api`.