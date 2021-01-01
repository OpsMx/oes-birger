TARGETS=test forwarder-controller forwarder-agent

PLATFORM=linux/amd64,linux/arm64

build=docker buildx build --pull --platform ${PLATFORM}

controller_deps = \
    ulid/ulid.go \
	controller/webhook/webhook.go \
	controller/controller.go \
	tunnel/time.go \
	tunnel/defaults.go \
	kubeconfig/config.go

agent_deps = \
	agent/agent.go \
    kubeconfig/config.go

pb_deps = go.mod tunnel/tunnel.proto

now = `date -u +%Y%m%dT%H%M%S`

all: ${TARGETS}

tunnel/tunnel.pb.go: ${pb_deps}
	protoc --go_out=plugins=grpc:tunnel tunnel/tunnel.proto

forwarder-controller: ${controller_deps} tunnel/tunnel.pb.go
	@${build} --tag docker.flame.org/library/forwarder-controller:latest --tag docker.flame.org/library/forwarder-controller:v${now} --target controller . --push

forwarder-agent: ${agent_deps} tunnel/tunnel.pb.go
	@${build} --tag docker.flame.org/library/forwarder-agent:latest  --tag docker.flame.org/library/forwarder-agent:v${now}  --target agent . --push

test:
	go test  -race ./...
