#
# Install the latest versions of our mods.  This is done as a separate step
# so it will pull from an image cache if possible, unless there are changes.
#
FROM golang:1.15.6-alpine AS buildmod
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
RUN go build -o /out/agent agent/*.go

#
# Compile the controller.
#
FROM buildmod AS build-controller
COPY . .
RUN mkdir /out
RUN go build -o /out/controller controller/*.go

#
# Build the agent image.  This should be a --target on docker build.
#
FROM scratch AS agent-image
WORKDIR /app
COPY --from=build-agent /out/agent /app
EXPOSE 9102
CMD ["/app/agent"]

#
# Build the controller image.  This should be a --target on docker build.
#
FROM scratch AS controller-image
WORKDIR /app
COPY --from=build-controller /out/controller /app
EXPOSE 9001-9002 9102
CMD ["/app/controller"]
