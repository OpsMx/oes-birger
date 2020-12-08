TARGETS=forwarder-controller forwarder-agent

PLATFORM=linux

build=DOCKER_BUILDKIT=1 docker build . --platform ${PLATFORM}

all: ${TARGETS}

forwarder-controller:
	@${build} --tag forwarder-controller:latest --target controller

forwarder-agent:
	@${build} --tag forwarder-agent:latest --target agent
