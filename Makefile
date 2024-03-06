all: build
docker: docker-build docker-push

.PHONY: bpf/*.o 
bpf/*.o: bpf/*.c
	go generate ./bpf/

.PHONY: build
build: bpf/*.o
	go build -o ./bin/xdp-gossip ./main.go

.PHONY: docker-build
docker-build:
	docker build -t kerwenwwer/gossip-service:latest .

.PHONY: docker-push
docker-push:
	docker push kerwenwwer/gossip-service:latest

.PHONY: docker-up
docker-up:
	docker-compose up --build
