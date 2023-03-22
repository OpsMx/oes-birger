#!/bin/sh

set -e

id="$1"
[ -n "$1" ] || id=01
echo $id

../../bin/client --configFile config/agent/config-${id}.yaml --profile
