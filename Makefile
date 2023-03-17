#
# Copyright 2021-2023 OpsMx, Inc.
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
BINARIES = client server make-ca get-creds

# These are the targets for Docker images, used both for the multi-arch and
# single (local) Docker builds.
# Dockerfiles should have a target that ends in -image, e.g. agent-image.
IMAGE_TARGETS = agent-client agent-controller

#
# Below here lies magic...
#

# Due to the way we build, we will make the universe no matter which files
# actually change.  With the many targets, this is just so much easier,
# and it also ensures the Docker images have identical timestamp-based tags.
pb_deps = internal/tunnel/tunnel.pb.go internal/tunnel/tunnel_grpc.pb.go
all_deps := ${pb_deps} $(shell find app internal -name '*.go' | grep -v _test) Makefile

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
# set git info details
#
set-git-info:
	@$(eval GIT_BRANCH=$(shell git describe --tags))
	@$(eval GIT_HASH=$(shell git rev-parse ${GIT_BRANCH}))

#
# Common components, like GRPC client code generation.
#

internal/tunnel/tunnel.pb.go: go.mod internal/tunnel/tunnel.proto
	protoc --go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		internal/tunnel/tunnel.proto

#
# Build locally, mostly for development speed.
#

.PHONY: local
local: $(addprefix bin/,$(BINARIES))

bin/%:: set-git-info ${all_deps}
	@[ -d bin ] || mkdir bin
	go build -o $@ \
		-ldflags="-X 'github.com/OpsMx/go-app-base/version.buildType=dev' -X 'github.com/OpsMx/go-app-base/version.gitHash=${GIT_HASH}' -X 'github.com/OpsMx/go-app-base/version.gitBranch=${GIT_BRANCH}'" \
		app/$(@F)/*.go

#
# Multi-architecture image builds
#
.PHONY: images
images: buildtime clean-image-names set-git-info $(addsuffix .tstamp, $(addprefix buildtime/,$(IMAGE_TARGETS)))

buildtime/%.tstamp:: ${all_deps} Dockerfile
	touch ${pb_deps}
	${BUILDX} \
		--tag ${IMAGE_PREFIX}$(patsubst %.tstamp,%,$(@F)):latest \
		--tag ${IMAGE_PREFIX}$(patsubst %.tstamp,%,$(@F)):${GIT_BRANCH} \
		--target $(patsubst %.tstamp,%,$(@F))-image \
		--build-arg GIT_HASH=${GIT_HASH} \
		--build-arg GIT_BRANCH=${GIT_BRANCH} \
		--build-arg BUILD_TYPE=release \
		-f Dockerfile \
		--push .
	echo >> buildtime/image-names.txt ${IMAGE_PREFIX}$(patsubst %.tstamp,%,$(@F)):latest
	echo >> buildtime/image-names.txt ${IMAGE_PREFIX}$(patsubst %.tstamp,%,$(@F)):${GIT_BRANCH}
	@touch $@

.PHONY: image-names
image-names:
	@echo ::set-output name=imageNames::$(shell echo `cat buildtime/image-names.txt` | sed 's/\ /,\ /g')

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
clean: clean-image-names
	rm -f buildtime/*.tstamp
	rm -f bin/*

.PHONY: really-clean
really-clean: clean
	rm -f ${pb_deps}

.PHONY: clean-image-names
clean-image-names:
	rm -f buildtime/image-names.txt
