#!/bin/bash -x

#  example usage: publishucapideb.sh lucid amd64 (devel|main|rc) [ branch ]

LINVER=$1
LINARCH=$2
REPO=$3
BRANCHPATH=$4

export FREIGHT_CONF=/etc/freight.internal.conf
cd /tmp/freeswitch${BRANCHPATH}/

freight add *.deb apt/$LINVER/$REPO

freight cache apt/$LINVER



