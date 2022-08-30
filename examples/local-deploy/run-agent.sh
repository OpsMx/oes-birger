#!/bin/sh

set -e

../../bin/forwarder-agent -caCertFile ca-cert.pem --configFile config/agent/config.yaml

