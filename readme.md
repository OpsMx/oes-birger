# grpc-bidir

This sample implements a bi-directional event stream using GRPC.

As a warning, this is my first attempt at any Go code...

# Prerequisites

`go get google.golang.org/protobuf/cmd/protoc-gen-go \
        google.golang.org/grpc/cmd/protoc-gen-go-grpc`

# Building

`protoc --proto_path=tunnel --go_out=tunnel --go_opt=paths=source_relative --go-grpc_out=tunnel --go-grpc_opt=paths=source_relative tunnel/tunnel.proto`

# Running

Start the server:
`go run server/server.go`

Start a client:
`go run client/client.go -identity skan1`

Send a request:
`go run sender/sender.go -identity skan1`
