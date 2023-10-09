FROM golang:1.19 AS ebpf-tcp-proxy

USER root

RUN apt-get update && apt-get install -y bpftool iproute2 lsof netcat-traditional tmux 

COPY ./bpf/* /bpf/
COPY bin/xdp-gossip /usr/local/bin/xdp-gossip
