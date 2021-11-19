#
# Copyright 2021 OpsMx, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

TARGETS=test local
PLATFORM=linux/amd64,linux/arm64
BUILDX=docker buildx build --pull --platform ${PLATFORM}
IMAGE_PREFIX=docker.flame.org/library/

#
# Build targets.  Adding to these will cause magic to occur.
#

# These are targets for "make local"
BINARIES = agent controller make-ca get-creds

# These are the targets for Docker images, used both for the multi-arch and
# single (local) Docker builds.
# Dockerfiles should have a target that ends in -image, e.g. agent-image.
IMAGE_TARGETS = controller agent make-ca
#
# Below here lies magic...
#

# Due to the way we build, we will make the universe no matter which files
# actually change.  With the many targets, this is just so much easier,
# and it also ensures the Docker images have identical timestamp-based tags.
pb_deps = pkg/tunnel/tunnel.pb.go pkg/tunnel/tunnel_grpc.pb.go
all_deps := ${pb_deps} $(shell find * -name '*.go' | grep -v _test)

now := $(shell date -u +%Y%m%dT%H%M%S)

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
	protoc --go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		pkg/tunnel/tunnel.proto

#
# Build locally, mostly for development speed.
#

.PHONY: local
local: $(addprefix bin/,$(BINARIES))

bin/%:: ${all_deps}
	@[ -d bin ] || mkdir bin
	go build -ldflags="-s -w" -o $@ app/$(@F)/*.go

#
# Multi-architecture image builds
#
.PHONY: images-ma
images-ma: buildtime $(addsuffix -ma.ts, $(addprefix buildtime/,$(IMAGE_TARGETS)))

buildtime/%-ma.ts:: ${all_deps} Dockerfile.multi
	${BUILDX} \
		--tag ${IMAGE_PREFIX}forwarder-$(patsubst %-ma.ts,%,$(@F)):latest \
		--tag ${IMAGE_PREFIX}forwarder-$(patsubst %-ma.ts,%,$(@F)):v${now} \
		--target $(patsubst %-ma.ts,%,$(@F))-image \
		-f Dockerfile.multi \
		--push .
	@touch $@

#
# Standard "whatever we are on now" image builds
#
.PHONY: images
images: $(addsuffix .ts, $(addprefix buildtime/,$(IMAGE_TARGETS)))

buildtime/%.ts:: buildtime ${all_deps} Dockerfile
	docker build \
		--tag ${IMAGE_PREFIX}forwarder-$(patsubst %.ts,%,$(@F)):latest \
		--tag ${IMAGE_PREFIX}forwarder-$(patsubst %.ts,%,$(@F)):v${now} \
		--target $(patsubst %.ts,%,$(@F))-image \
		.
	touch $@

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
	rm -f buildtime/*.ts
	rm -f bin/*

.PHONY: really-clean
really-clean: clean
	rm -f ${pb_deps}
