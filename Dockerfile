# Use golang:1.19 as the base image for building ebpf-tcp-proxy
FROM golang:1.19 AS eGossip

# Run as root for package installations and configurations
USER root

# Combine package installations into a single RUN command to reduce layers,
# adding --no-install-recommends to minimize image size and
# cleaning up the apt cache to reduce unnecessary bloat
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    bpftool \
    iproute2 \
    lsof \
    netcat-traditional \
    iputils-ping \
    net-tools && \
    rm -rf /var/lib/apt/lists/*  # This command removes the apt cache

# Copy necessary files from the host to the container filesystem
COPY bpf/* /bpf/
COPY bin/xdp-gossip /usr/local/bin/xdp-gossip
COPY k8s/entrypoint.sh /entrypoint.sh

# Ensure the entrypoint script is executable
RUN chmod +x /entrypoint.sh

# Set the entrypoint script to run when the container starts
ENTRYPOINT ["/entrypoint.sh"]
