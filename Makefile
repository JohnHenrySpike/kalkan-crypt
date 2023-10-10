.DEFAULT_GOAL := help

LIB=kalkancrypt.so

IMAGE_NAME = kalkanphp
DOCKER_RUN = docker run -u$(shell id -u):$(shell id -u) --rm -v ./:/app

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

composer_install: ## install dependencies for dev
	$(DOCKER_RUN) $(IMAGE_NAME) composer i
test: ## run tests case
	$(DOCKER_RUN) $(IMAGE_NAME) composer run-script test
build: ## build image
	docker build . -t $(IMAGE_NAME)

up: composer_install test

default: help
