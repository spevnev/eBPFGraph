#!/bin/bash

set -e
set -o pipefail

# Create cgroup if it doesn't exist
CGROUP="/sys/fs/cgroup/client"
mkdir -p $CGROUP

# Add current process to it
echo $$ > $CGROUP/cgroup.procs

while true; do
    echo "test" | nc -w0 127.0.0.1 1234 &
    sleep 0.01s
done
