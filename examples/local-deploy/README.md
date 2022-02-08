# Run Stuff Locally

This is an example of how to run the controller and agent locally,
with a bi-directional tunnel.  A "whoami" type server will be started
which can be accessed from either the controller or agent, and
services will be configured for both.

Additionally, the agent will have a "loopback" service that talks back
to the whoami-agent endpoint, allowing a test of mutations on headers
using simple curl commands to the controller.

# Running Things

1. Run `make` at the top level of this project.
1. `sh setup.sh` to create keys.
1. `sh run-controller.sh` to run the controller.
1. `sh run-agent.sh` to run the agent.
1. `docker run -d --name  whoami -P traefik/whoami --port 8300` to run the whoami service, on port 8300.

If any of the ports used need to be changed, edit the configs or command lines.

Run each of the `run-` shell commands in a new window, so you can run all three at once.

# Testing things

`curl http://localhost:8001` will connect to the controller, which will forward the
request to the agent, which will connect to the `whoami` service and report the
reply.

`curl http://localhost:8101` will connect to the agent, which will forward the request
to the controller, which will connect to the `whoam` service and report the reply.

`curl http://localhost:8002` will connect to the controller, which will send the request
to the agent, loop the response back through the agent via port 8101, and reply.  This
is to test end-to-end X-Spinnaker-User header mutations.

`curl http://localhost:8300` will connect directly to the whoami container.
