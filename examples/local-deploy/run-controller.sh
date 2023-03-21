#!/bin/sh

set -e

../../bin/server --configFile config/controller/config.yaml --profile --jwt-agent-names smith,mocha,leo,wesley
