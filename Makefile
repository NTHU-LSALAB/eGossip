all: bpf/*.o build docker-up

bpf/*.o: bpf/*.c
	go generate ./bpf/..

.PHONY: build
build: bpf/*.o
	go build -o ./bin/xdp-gossip ./main.go

.PHONY: docker-build
docker-build:
	docker build -t xdp-gossip .

.PHONY: docker-up
docker-up:
	docker-compose up --build