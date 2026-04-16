BINARY ?= rke2-patcher
COMPONENT ?= traefik

.PHONY: help build version image-cve image-list image-patch test-docker-default test-docker-calico-traefik

help:
	@echo "Targets:"
	@echo "  make build"
	@echo "  make version"
	@echo "  make image-cve COMPONENT=traefik"
	@echo "  make image-list COMPONENT=traefik"
	@echo "  make image-patch COMPONENT=traefik"
	@echo "  make test-docker-default"
	@echo "  make test-docker-calico-traefik"

build:
	go build -o $(BINARY) .

version: build
	./$(BINARY) --version

image-cve: build
	./$(BINARY) image-cve $(COMPONENT)

image-list: build
	./$(BINARY) image-list $(COMPONENT)

image-patch: build
	./$(BINARY) image-patch $(COMPONENT)

test-docker-default: build
	go test -v -timeout=80m ./tests/docker/default_components/default_components_test.go -ginkgo.v -rke2Version v1.35.3+rke2r3 -patcherBin ./$(BINARY)

test-docker-calico-traefik: build
	go test -v -timeout=80m ./tests/docker/calico_traefik/calico_traefik_test.go -ginkgo.v -rke2Version v1.35.3+rke2r3 -patcherBin ./$(BINARY)
