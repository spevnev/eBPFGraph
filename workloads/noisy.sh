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

echo "Started server and clients"

DIR=$(dirname $0)

$DIR/jobs/server.sh &
for i in $(seq 1 20); do
    $DIR/jobs/client.sh &
done

echo "Press any key to start noisy process"
read -rsn1

# Create cgroup if it doesn't exist
CGROUP="/sys/fs/cgroup/noisy"
mkdir -p $CGROUP

# Add current process to it
echo $$ > $CGROUP/cgroup.procs

CPUS=$(($(nproc --all) * 4))
stress -q --cpu $CPUS &

echo "Press any key to stop the workload"
read -rsn1
kill $(jobs -p)
