BIN := bin/merkle

.PHONY: all build test clean
all: build

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/merkle

test:
	go test ./...

clean:
	rm -rf bin
