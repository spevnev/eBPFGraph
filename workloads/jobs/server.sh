#!/bin/bash

set -e
set -o pipefail

# Create cgroup if it doesn't exist
CGROUP="/sys/fs/cgroup/server"
mkdir -p $CGROUP

# Add current process to it
echo $$ > $CGROUP/cgroup.procs

nc -k -l 1234 > /dev/null
