#!/bin/bash

# Specify the container name or ID
CONTAINER_NAME_OR_ID="xdp-gossip-gossip_service1-1"

# Find the PID of the container
PID=$(docker inspect --format '{{ .State.Pid }}' $CONTAINER_NAME_OR_ID)

if [ -z "$PID" ]; then
    echo "Container not found or no PID available."
    exit 1
fi
echo $PID
# Run strace and process the output
echo > strace_output.txt
sudo strace -f -e trace=recvfrom -p $PID 2> strace_output.txt 

