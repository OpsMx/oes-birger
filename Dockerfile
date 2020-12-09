#
# Install the latest versions of our mods.  This is done as a separate step
# so it will pull from an image cache if possible, unless there are changes.
#
FROM --platform=${BUILDPLATFORM} golang:1.15.6-alpine AS buildmod
ENV CGO_ENABLED=0
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download

#
# Compile the agent.
#
FROM buildmod AS build-agent
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /build/agent agent/agent.go

#
# Compile the controller.
#
FROM buildmod AS build-controller
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /build/controller controller/controller.go

#
# Build the agent image.  This should be a --target on docker build.
#
FROM alpine AS agent
WORKDIR /app
COPY --from=build-agent /build/agent /app
CMD ["/app/agent"]

#
# Build the controller image.  This should be a --target on docker build.
#
FROM alpine AS controller
WORKDIR /app
COPY --from=build-controller /build/controller /app
EXPOSE 9001-9002
CMD ["/app/controller"]
