#
# Install the latest versions of our mods.  This is done as a separate step
# so it will pull from an image cache if possible, unless there are changes.
#
FROM golang:1.16.2-alpine AS buildmod
ENV CGO_ENABLED=0
RUN mkdir /build
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download

#
# Compile the agent.
#
FROM buildmod AS build-binaries
COPY . .
RUN mkdir /out /out/agent-binaries
RUN go build -o /out/agent app/agent/*.go
RUN go build -o /out/controller app/controller/*.go
RUN go build -o /out/make-ca app/make-ca/*.go
# Also build the different OS versions here, so we can publish them.
RUN GOOS=linux GOARCH=amd64 go build -o /out/agent-binaries/agent.amd64.latest app/agent/*.go
RUN GOOS=linux GOARCH=arm64 go build -o /out/agent-binaries/agent.arm64.latest app/agent/*.go

#
# Build the agent image.  This should be a --target on docker build.
#
FROM scratch AS agent-image
WORKDIR /app
COPY --from=build-binaries /out/agent /app
EXPOSE 9102
CMD ["/app/agent"]

#
# Build the controller image.  This should be a --target on docker build.
# Note that the agent is also added, so the binary can be served from
# the controller to auto-update the remote agent.
#
FROM scratch AS controller-image
WORKDIR /app
COPY --from=build-binaries /out/controller /app
COPY --from=build-binaries /out/agent-binaries /app/agent-binaries
EXPOSE 9001-9002 9102
CMD ["/app/controller"]

#
# Build the make-ca image.  This should be a --target on docker build.
#
FROM scratch AS make-ca-image
WORKDIR /app
COPY --from=build-binaries /out/make-ca /app
CMD ["/app/make-ca"]
