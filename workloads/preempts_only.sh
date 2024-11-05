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

DIR=$(dirname $0)

$DIR/jobs/server.sh &
for i in $(seq 1 20); do
    $DIR/jobs/client.sh &
done

echo "Press any key to stop the workload"
read -rsn1
kill $(jobs -p)
