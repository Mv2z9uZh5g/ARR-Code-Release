.PHONY: build run test lint migrate-up migrate-down clean

BINARY_NAME=server
BUILD_DIR=./bin

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

test:
	go test -race -count=1 ./...

test-integration:
	go test -race -count=1 -tags=integration ./...

lint:
	golangci-lint run ./...

migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down

generate:
	sqlc generate

clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache
