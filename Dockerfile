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

#
# Install the latest versions of our mods.  This is done as a separate step
# so it will pull from an image cache if possible, unless there are changes.
#
FROM --platform=${BUILDPLATFORM} golang:1.20-alpine AS buildmod
RUN mkdir /build
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download

FROM buildmod AS build-setup
RUN mkdir /out
ARG GIT_BRANCH
ARG GIT_HASH
ARG BUILD_TYPE
ARG TARGETOS
ARG TARGETARCH
ENV GIT_BRANCH=${GIT_BRANCH} GIT_HASH=${GIT_HASH} BUILD_TYPE=${BUILD_TYPE}
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
COPY . .
RUN touch internal/tunnel/tunnel.pb.go

#
# Compile the client-side binaries.
#
FROM build-setup AS build-client-binaries
RUN go build -ldflags="-X 'github.com/OpsMx/go-app-base/version.buildType=${BUILD_TYPE}' -X 'github.com/OpsMx/go-app-base/version.gitHash=${GIT_HASH}' -X 'github.com/OpsMx/go-app-base/version.gitBranch=${GIT_BRANCH}'" -o /out/agent-client app/client/*.go

#
# Compile the server-side binaries.
#
FROM build-setup AS build-server-binaries
RUN go build -ldflags="-X 'github.com/OpsMx/go-app-base/version.buildType=${BUILD_TYPE}' -X 'github.com/OpsMx/go-app-base/version.gitHash=${GIT_HASH}' -X 'github.com/OpsMx/go-app-base/version.gitBranch=${GIT_BRANCH}'" -o /out/agent-controller app/server/*.go
RUN go build -ldflags="-X 'github.com/OpsMx/go-app-base/version.buildType=${BUILD_TYPE}' -X 'github.com/OpsMx/go-app-base/version.gitHash=${GIT_HASH}' -X 'github.com/OpsMx/go-app-base/version.gitBranch=${GIT_BRANCH}'" -o /out/make-ca app/make-ca/*.go
RUN go build -ldflags="-X 'github.com/OpsMx/go-app-base/version.buildType=${BUILD_TYPE}' -X 'github.com/OpsMx/go-app-base/version.gitHash=${GIT_HASH}' -X 'github.com/OpsMx/go-app-base/version.gitBranch=${GIT_BRANCH}'" -o /out/get-creds app/get-creds/*.go

#
# Establish a base OS image used by all the applications.
#
FROM alpine:3 AS base-image
RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates curl
# the exit 0 hack is a work-around to build on ARM64 apparently...
RUN update-ca-certificates ; exit 0
RUN mkdir /local /local/ca-certificates && rm -rf /usr/local/share/ca-certificates && ln -s  /local/ca-certificates /usr/local/share/ca-certificates
COPY docker/run.sh /app/run.sh
ENTRYPOINT ["/bin/sh", "/app/run.sh"]

#
# Build the agent image.  This should be a --target on docker build.
#
FROM base-image AS agent-client-image
WORKDIR /app
COPY --from=build-client-binaries /out/agent-client /app
EXPOSE 9102
CMD ["/app/agent-client"]

#
# Build the controller image.  This should be a --target on docker build.
# Note that the agent is also added, so the binary can be served from
# the controller to auto-update the remote agent.
#
FROM base-image AS agent-controller-image
WORKDIR /app
COPY --from=build-server-binaries /out/agent-controller /app
COPY --from=build-server-binaries /out/make-ca /app
COPY --from=build-server-binaries /out/get-creds /app
EXPOSE 9001-9002 9102
CMD ["/app/agent-controller"]
