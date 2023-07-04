all: bpf/*.o build docker-build

bpf/*.o: bpf/*.c
	go generate ./bpf/..

.PHONY: build
build: bpf/*.o
	go build -o ./bin/xdp-gossip ./main.go

.PHONY: docker-build
docker-build:
	docker build -t xdp-gossip .