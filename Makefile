.DEFAULT_GOAL := help

LIB=kalkancrypt.so

IMAGE_NAME = kalkanphp
DOCKER_RUN_ROOT = docker run --rm -v ./:/app
DOCKER_RUN = $(DOCKER_RUN_ROOT) -u$(shell id -u):$(shell id -u)

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

composer_install: ## install dependencies for dev
	$(DOCKER_RUN) $(IMAGE_NAME) composer i
test: ## run tests case
	$(DOCKER_RUN) $(IMAGE_NAME) composer run-script test
test-with-certs: ## run tests case (ca certs loaded)
	docker run -v ./:/app $(IMAGE_NAME) sh -c "cp -a tests/fixtures/CaCerts/*.crt /usr/local/share/ca-certificates/extra/ && update-ca-certificates && composer run-script test-with-certs"
build: ## build image
	docker build . -t $(IMAGE_NAME)

up: build composer_install test

default: help
