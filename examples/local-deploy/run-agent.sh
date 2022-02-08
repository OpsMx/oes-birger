#!/bin/sh

set -e

../../bin/agent -caCertFile ca-cert.pem --configFile config/agent/config.yaml

