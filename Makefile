TARGETS=test local
PLATFORM=linux/amd64,linux/arm64
BUILDX=docker buildx build --pull --platform ${PLATFORM}
IMAGE_PREFIX=docker.flame.org/library/

# Generated protobuf outputs.  These are removed with "make clean"
pb_deps = tunnel/tunnel.pb.go

controller_deps = ${pb_deps} \
    ulid/ulid.go \
	controller/webhook/webhook.go \
	controller/controller.go \
	controller/config.go \
	tunnel/time.go \
	tunnel/defaults.go \
	kubeconfig/config.go

agent_deps = ${pb_deps} \
	agent/agent.go \
	agent/config.go \
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
	go build -o bin/agent agent/*.go


bin/controller: ${controller_deps}
	[ -d bin ] || mkdir bin
	go build -o bin/controller controller/*.go

#
# Multi-architecture image builds
#
.PHONY: images-ma
images-ma: forwarder-controller-ma-image forwarder-agent-ma-image

.PHONY: forwarder-agent-ma-image
forwarder-agent-ma-image: forwarder-agent-ma-image.buildtime

.PHONY: forwarder-controller-ma-image
forwarder-controller-ma-image: forwarder-controller-ma-image.buildtime

forwarder-agent-ma-image.buildtime: ${agent_deps} Dockerfile.multi
	@${BUILDX} \
		--tag ${IMAGE_PREFIX}forwarder-agent:latest \
		--tag ${IMAGE_PREFIX}forwarder-agent:v${now} \
		--target agent-image \
		-f Dockerfile.multi \
		--push .
	touch forwarder-agent-ma-image.buildtime

forwarder-controller-ma-image.buildtime: ${controller_deps} Dockerfile.multi
	@${BUILDX} \
	    --tag ${IMAGE_PREFIX}forwarder-controller:latest \
		--tag ${IMAGE_PREFIX}forwarder-controller:v${now} \
		--target controller-image \
		-f Dockerfile.multi \
		--push .
	touch forwarder-controller-ma-image.buildtime


#
# Standard "whatever we are on now" image builds
#
.PHONY: images
images: forwarder-controller-image forwarder-agent-image

.PHONY: forwarder-agent-image
forwarder-agent-image: forwarder-agent-image.buildtime

.PHONY: forwarder-controller-image
forwarder-controller-image: forwarder-controller-image.buildtime

forwarder-agent-image.buildtime: ${agent_deps} Dockerfile
	@docker build \
		--tag ${IMAGE_PREFIX}forwarder-agent:latest \
		--tag ${IMAGE_PREFIX}forwarder-agent:v${now} \
		--target agent-image \
		.
	@echo Tags: ${IMAGE_PREFIX}forwarder-agent:latest ${IMAGE_PREFIX}forwarder-agent:v${now}
	touch forwarder-agent-image.buildtime

forwarder-controller-image.buildtime: ${controller_deps} Dockerfile
	@docker build \
	    --tag ${IMAGE_PREFIX}forwarder-controller:latest \
		--tag ${IMAGE_PREFIX}forwarder-controller:v${now} \
		--target controller-image \
		.
	@echo Tags: ${IMAGE_PREFIX}forwarder-controller:latest ${IMAGE_PREFIX}forwarder-controller:v${now}
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
