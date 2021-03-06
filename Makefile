TARGETS=test local
PLATFORM=linux/amd64,linux/arm64
BUILDX=docker buildx build --pull --platform ${PLATFORM}
IMAGE_PREFIX=docker.flame.org/library/

# Generated protobuf outputs.  These are removed with "make clean"
pb_deps = pkg/tunnel/tunnel.pb.go

controller_deps = ${pb_deps} \
	pkg/ca/ca.go \
	app/controller/agent-tracker.go \
	app/controller/config.go \
	app/controller/controller.go \
	app/controller/grpc-server.go \
	app/controller/cnc-server.go \
	app/controller/webhook/webhook.go \
	pkg/tunnel/time.go \
	pkg/tunnel/defaults.go \
	pkg/kubeconfig/config.go \
    pkg/ulid/ulid.go

agent_deps = ${pb_deps} \
	app/agent/agent.go \
	app/agent/config.go \
    pkg/kubeconfig/config.go

make_ca_deps = \
	app/make-ca/make-ca.go \
	pkg/ca/ca.go

now = `date -u +%Y%m%dT%H%M%S`

#
# Default target.
#

.PHONY: all
all: ${TARGETS}

#
# Common components, like GRPC client code generation.
#

pkg/tunnel/tunnel.pb.go: go.mod pkg/tunnel/tunnel.proto
	protoc --go_out=plugins=grpc:pkg/tunnel pkg/tunnel/tunnel.proto

#
# Build locally, mostly for development speed.
#

.PHONY: local
local: bin/agent bin/controller bin/make-ca

bin/agent: ${agent_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/agent app/agent/*.go

bin/controller: ${controller_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/controller app/controller/*.go

bin/make-ca: ${make_ca_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/make-ca app/make-ca/*.go

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
