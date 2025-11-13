.PHONY: all certgen test clean

all: certgen

certgen: ## Build the certgen binary
	CGO_ENABLED=0 go build -mod=vendor -o $@ .
	strip $@

test: ## Run the unit tests
	go test --mod=vendor ./...

clean: ## Remove build artifacts
	rm -rf certgen

DOCKER_IMAGE ?= quay.io/cilium/certgen:latest
docker-image: ## Build the docker image
	docker buildx build --platform $(shell uname -m) -t $(DOCKER_IMAGE) . -f Dockerfile -o type=docker

CLUSTER ?= kind
docker-image-load: docker-image ## Build and load the image to the cluster
	kind load docker-image $(DOCKER_IMAGE) --name $(CLUSTER)

docker-image-push: docker-image ## Build and push the image to the registry
	docker push $(DOCKER_IMAGE)

help: ## Print this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9][a-zA-Z0-9 _-]*:.*?##/ { split($$1, targets, " "); for (i in targets) { printf "  \033[36m%-28s\033[0m %s\n", targets[i], $$2 } } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
