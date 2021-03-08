TARGETS=test local
PLATFORM=linux/amd64,linux/arm64
BUILDX=docker buildx build --pull --platform ${PLATFORM}
IMAGE_PREFIX=docker.flame.org/library/

#
# Build targets.  Adding to these will cause magic to occur.
#

# These are targets for "make local"
BINARIES = agent controller make-ca remote-command


#
# Below here lies magic...
#

# Generated protobuf outputs.  These are removed with "make clean"
pb_deps = pkg/tunnel/tunnel.pb.go

gofiles = ${pb_deps} $(shell find * -name '*.go' | grep -v _test)

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
local: $(addprefix bin/,$(BINARIES))

bin/%:: ${all_deps}
	@[ -d bin ] || mkdir bin
	go build -o bin/$@ app/$(@F)/*.go

#
# Multi-architecture image builds
#
.PHONY: images-ma
images-ma: forwarder-controller-ma-image forwarder-agent-ma-image forwarder-make-ca-ma-image

.PHONY: forwarder-agent-ma-image
forwarder-agent-ma-image: buildtime buildtime/forwarder-agent-ma-image.buildtime

.PHONY: forwarder-agent-ma-alpine-image
forwarder-agent-ma-alpine-image: buildtime buildtime/forwarder-agent-ma-alpine-image.buildtime

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

buildtime/forwarder-agent-ma-alpine-image.buildtime: ${agent_deps} Dockerfile.multi
	@${BUILDX} \
		--tag ${IMAGE_PREFIX}forwarder-agent-alpine:latest \
		--tag ${IMAGE_PREFIX}forwarder-agent-alpine:v${now} \
		--target agent-image-alpine \
		-f Dockerfile.multi \
		--push .
	touch buildtime/forwarder-agent-ma-alpine-image.buildtime

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
