TARGETS=test forwarder-controller forwarder-agent

PLATFORM=linux/amd64,linux/arm64,linux/arm/v7

build=docker buildx build --pull --platform ${PLATFORM}

all: ${TARGETS}

tunnel/tunnel.pb.go: tunnel/tunnel.proto
	protoc --go_out=plugins=grpc:tunnel tunnel/tunnel.proto

forwarder-controller: tunnel/tunnel.pb.go
	@${build} --tag docker.flame.org/library/forwarder-controller:latest --target controller . --push

forwarder-agent: tunnel/tunnel.pb.go
	@${build} --tag docker.flame.org/library/forwarder-agent:latest --target agent . --push

test:
	go test  -race ./...
