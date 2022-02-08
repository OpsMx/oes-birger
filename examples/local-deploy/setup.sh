#!/bin/sh

set -e

[ -r ca-cert.pem ] && {
    echo "ca-cert.pem exists.  Run sh clean.sh to reset before running this script."
    exit 1
}

../../bin/make-ca --withKubernetes=false --alsoAgentNamed=smith
