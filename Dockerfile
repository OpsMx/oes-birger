#
# Install the latest versions of our mods.  This is done as a separate step
# so it will pull from an image cache if possible, unless there are changes.
#
FROM golang:1.16.0-alpine AS buildmod
ENV CGO_ENABLED=0
RUN mkdir /build
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download

#
# Compile the agent.
#
FROM buildmod AS build-agent
COPY . .
RUN mkdir /out
RUN go build -o /out/agent app/agent/*.go

#
# Compile the controller.
#
FROM buildmod AS build-controller
COPY . .
RUN mkdir /out
RUN go build -o /out/controller app/controller/*.go

#
# Compile make-ca.
#
FROM buildmod AS build-make-ca
COPY . .
RUN mkdir /out
RUN go build -o /out/make-ca app/make-ca/*.go

#
# Build the agent image.  This should be a --target on docker build.
#
FROM scratch AS agent-image
WORKDIR /app
COPY --from=build-agent /out/agent /app
EXPOSE 9102
CMD ["/app/agent"]

#
# Build the agent-alpine image.  This should be a --target on docker build.
#
FROM alpine:3.12 AS agent-alpine-image
WORKDIR /app
COPY --from=build-agent /out/agent /app
EXPOSE 9102
CMD ["/app/agent"]

#
# Build the controller image.  This should be a --target on docker build.
# Note that the agent is also added, so the binary can be served from
# the controller to auto-update the remote agent.
#
FROM scratch AS controller-image
WORKDIR /app
COPY --from=build-controller /out/controller /app
COPY --from=build-agent /out/agent /app/agent-binaries/agent.latest
EXPOSE 9001-9002 9102
CMD ["/app/controller"]

#
# Build the make-ca image.  This should be a --target on docker build.
#
FROM scratch AS make-ca-image
WORKDIR /app
COPY --from=build-make-ca /out/make-ca /app
CMD ["/app/make-ca"]
