#!/bin/bash

set -e
set -o pipefail

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: run as root"
    exit 1
fi

if [ "$(mount -l | grep cgroup2)" = "" ]; then
    echo "ERROR: cgroup v2 is required"
    exit 1
fi

# Create cgroup if it doesn't exist
CGROUP="/sys/fs/cgroup/client"
mkdir -p $CGROUP

# Add current process to it
echo $$ > $CGROUP/cgroup.procs

while true; do
    curl localhost:3000 > /dev/null 2>&1
    sleep 0.01s
done
