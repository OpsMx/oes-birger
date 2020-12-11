TARGETS=test forwarder-controller forwarder-agent

PLATFORM=linux/amd64,linux/arm64,linux/arm/v7

build=docker buildx build --pull --platform ${PLATFORM}

all: ${TARGETS}

forwarder-controller:
	@${build} --tag docker.flame.org/library/forwarder-controller:latest --target controller . --push

forwarder-agent:
	@${build} --tag docker.flame.org/library/forwarder-agent:latest --target agent . --push

test:
	go test -p 1 ./...
