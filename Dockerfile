FROM golang:1.19 AS ebpf-tcp-proxy

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof netcat-traditional tmux net-tools

COPY bpf/* /bpf/
COPY bin/xdp-gossip /usr/local/bin/xdp-gossip

COPY k8s/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]