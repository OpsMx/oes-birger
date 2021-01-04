TARGETS=test local
PLATFORM=linux/amd64,linux/arm64
BUILD=docker buildx build --pull --platform ${PLATFORM}

# Generated protobuf outputs.  These are removed with "make clean"
pb_deps = tunnel/tunnel.pb.go

controller_deps = ${pb_deps} \
    ulid/ulid.go \
	controller/webhook/webhook.go \
	controller/controller.go \
	tunnel/time.go \
	tunnel/defaults.go \
	kubeconfig/config.go

agent_deps = ${pb_deps} \
	agent/agent.go \
    kubeconfig/config.go

now = `date -u +%Y%m%dT%H%M%S`

#
# Default target.
#

.PHONY: all
all: ${TARGETS}

#
# Common components, like GRPC client code generation.
#

tunnel/tunnel.pb.go: go.mod tunnel/tunnel.proto
	protoc --go_out=plugins=grpc:tunnel tunnel/tunnel.proto

#
# Build locally, mostly for development speed.
#

.PHONY: local
local: bin/agent bin/controller

bin/agent: ${agent_deps}
	[ -d bin ] || mkdir bin
	go build -o bin/agent agent/agent.go


bin/controller: ${controller_deps}
	[ -d bin ] || mkdir bin
	go build -o bin/controller controller/controller.go

#
# Image builds
#
.PHONY: images
images: forwarder-controller-image forwarder-agent-image

.PHONY: forwarder-agent-image
forwarder-agent-image: forwarder-agent-image.buildtime

.PHONY: forwarder-controller-image
forwarder-controller-image: forwarder-controller-image.buildtime

forwarder-agent-image.buildtime: ${agent_deps} Dockerfile
	@${BUILD} \
		--tag docker.flame.org/library/forwarder-agent:latest \
		--tag docker.flame.org/library/forwarder-agent:v${now} \
		--target agent-image . \
		--push
	touch forwarder-agent-image.buildtime

forwarder-controller-image.buildtime: ${controller_deps} Dockerfile
	@${BUILD} \
	    --tag docker.flame.org/library/forwarder-controller:latest \
		--tag docker.flame.org/library/forwarder-controller:v${now} \
		--target controller-image . \
		--push
	touch forwarder-controller-image.buildtime

#
# Test targets
#

.PHONY: test
test: ${pb_deps}
	go test  -race ./...

#
# Clean the world.
#

.PHONY: clean
clean:
	rm -f *.buildtime
	rm -f ${pb_deps}
	rm -f bin/*
