#!/bin/sh

set -e

[ -r control-token ] && {
    echo "control-token exists.  Run sh clean.sh to reset before running this script."
    exit 1
}

../../bin/server --configFile config/controller/config.yaml --generate-agent-tokens smith > agent-token
../../bin/server --configFile config/controller/config.yaml --generate-control-tokens smith > control-token
