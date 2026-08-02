.PHONY: build push deploy lint test clean

IMAGE_REPO := 847291046381.dkr.ecr.us-west-2.amazonaws.com/data-api
IMAGE_TAG := $(shell git rev-parse --short HEAD)

build:
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) -t $(IMAGE_REPO):latest .

push: build
	aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $(IMAGE_REPO)
	docker push $(IMAGE_REPO):$(IMAGE_TAG)
	docker push $(IMAGE_REPO):latest

deploy-staging: push
	./deploy.sh staging $(IMAGE_TAG)

deploy-prod: push
	DEPLOY_APPROVED=1 ./deploy.sh production $(IMAGE_TAG)

lint:
	golangci-lint run ./...
	helm lint ./charts/data-api

test:
	go test -race -count=1 ./...

clean:
	docker rmi $(IMAGE_REPO):$(IMAGE_TAG) || true
	docker rmi $(IMAGE_REPO):latest || true
