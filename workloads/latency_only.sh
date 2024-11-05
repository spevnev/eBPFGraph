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
CGROUP="/sys/fs/cgroup/throttled_cpu"
mkdir -p $CGROUP

# Throttle it
echo "100000 1000000" > $CGROUP/cpu.max

# Add current process to it
echo $$ > $CGROUP/cgroup.procs

CPUS=$(($(nproc --all) * 2 + 1))
while true; do
    stress -q --cpu $CPUS -t 1
done
