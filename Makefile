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
	pkg/webhook/webhook.go \
	pkg/tunnel/time.go \
	pkg/tunnel/defaults.go \
	pkg/kubeconfig/config.go \
    pkg/ulid/ulid.go

agent_deps = ${pb_deps} \
	app/agent/agent.go \
	app/agent/cancel.go \
	app/agent/command.go \
	app/agent/config.go \
	app/agent/kubernetes.go \
	app/agent/http.go \
    pkg/kubeconfig/config.go \
	pkg/tunnel/defaults.go \
	pkg/tunnel/time.go

make_ca_deps = \
	app/make-ca/make-ca.go \
	pkg/ca/ca.go

remote_command_deps = ${pb_deps} \
	app/remote-command/main.go

now = `date -u +%Y%m%dT%H%M%S`

#
# Default target.
#

.PHONY: all
all: ${TARGETS}

#
# make a buildtime directory to hold the build timestamp files
buildtime:
	[ ! -d buildtime ] && mkdir buildtime

#
# Common components, like GRPC client code generation.
#

pkg/tunnel/tunnel.pb.go: go.mod pkg/tunnel/tunnel.proto
	protoc --go_out=plugins=grpc:pkg/tunnel pkg/tunnel/tunnel.proto

#
# Build locally, mostly for development speed.
#

.PHONY: local
local: bin/agent bin/controller bin/make-ca bin/remote-command

bin/agent: ${agent_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/agent app/agent/*.go

bin/controller: ${controller_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/controller app/controller/*.go

bin/make-ca: ${make_ca_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/make-ca app/make-ca/*.go

bin/remote-command: ${remote_command_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/remote-command app/remote-command/*.go

#
# Multi-architecture image builds
#
.PHONY: images-ma
images-ma: forwarder-controller-ma-image forwarder-agent-ma-image forwarder-make-ca-ma-image

.PHONY: forwarder-agent-ma-image
forwarder-agent-ma-image: buildtime buildtime/forwarder-agent-ma-image.buildtime

.PHONY: forwarder-controller-ma-image
forwarder-controller-ma-image: buildtime buildtime/forwarder-controller-ma-image.buildtime

.PHONY: forwarder-make-ca-ma-image
forwarder-make-ca-ma-image: buildtime buildtime/forwarder-make-ca-ma-image.buildtime

buildtime/forwarder-agent-ma-image.buildtime: ${agent_deps} Dockerfile.multi
	@${BUILDX} \
		--tag ${IMAGE_PREFIX}forwarder-agent:latest \
		--tag ${IMAGE_PREFIX}forwarder-agent:v${now} \
		--target agent-image \
		-f Dockerfile.multi \
		--push .
	touch buildtime/forwarder-agent-ma-image.buildtime

buildtime/forwarder-controller-ma-image.buildtime: ${controller_deps} Dockerfile.multi
	@${BUILDX} \
	    --tag ${IMAGE_PREFIX}forwarder-controller:latest \
		--tag ${IMAGE_PREFIX}forwarder-controller:v${now} \
		--target controller-image \
		-f Dockerfile.multi \
		--push .
	touch buildtime/forwarder-controller-ma-image.buildtime

buildtime/forwarder-make-ca-ma-image.buildtime: ${make_ca_deps} Dockerfile.multi
	@${BUILDX} \
	    --tag ${IMAGE_PREFIX}forwarder-make-ca:latest \
		--tag ${IMAGE_PREFIX}forwarder-make-ca:v${now} \
		--target make-ca-image \
		-f Dockerfile.multi \
		--push .
	touch buildtime/forwarder-make-ca-ma-image.buildtime

#
# Standard "whatever we are on now" image builds
#
.PHONY: images
images: forwarder-controller-image forwarder-agent-image forwarder-make-ca-image

.PHONY: forwarder-agent-image
forwarder-agent-image: buildtime buildtime/forwarder-agent-image.buildtime

.PHONY: forwarder-controller-image
forwarder-controller-image: buildtime buildtime/forwarder-controller-image.buildtime

.PHONY: forwarder-make-ca-image
forwarder-make-ca-image: buildtime buildtime/forwarder-make-ca-image.buildtime

buildtime/forwarder-agent-image.buildtime: ${agent_deps} Dockerfile
	@docker build \
		--tag ${IMAGE_PREFIX}forwarder-agent:latest \
		--tag ${IMAGE_PREFIX}forwarder-agent:v${now} \
		--target agent-image \
		.
	@echo Tags: ${IMAGE_PREFIX}forwarder-agent:latest ${IMAGE_PREFIX}forwarder-agent:v${now}
	touch buildtime/forwarder-agent-image.buildtime

buildtime/forwarder-controller-image.buildtime: ${controller_deps} Dockerfile
	@docker build \
	    --tag ${IMAGE_PREFIX}forwarder-controller:latest \
		--tag ${IMAGE_PREFIX}forwarder-controller:v${now} \
		--target controller-image \
		.
	@echo Tags: ${IMAGE_PREFIX}forwarder-controller:latest ${IMAGE_PREFIX}forwarder-controller:v${now}
	touch buildtime/forwarder-controller-image.buildtime

buildtime/forwarder-make-ca-image.buildtime: ${make_ca_deps} Dockerfile
	@docker build \
	    --tag ${IMAGE_PREFIX}forwarder-make-ca:latest \
		--tag ${IMAGE_PREFIX}forwarder-make-ca:v${now} \
		--target make-ca-image \
		.
	@echo Tags: ${IMAGE_PREFIX}forwarder-make-ca:latest ${IMAGE_PREFIX}forwarder-make-ca:v${now}
	touch buildtime/forwarder-make-ca-image.buildtime

#
# Test targets
#

.PHONY: test
test: ${pb_deps}
	go test -race ./...

#
# Clean the world.
#

.PHONY: clean
clean:
	rm -f buildtime/*.buildtime
	rm -f ${pb_deps}
	rm -f bin/*
