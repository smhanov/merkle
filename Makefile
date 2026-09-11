BIN := bin/merkle

.PHONY: all build test testfull clean
all: build

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/merkle

test:
	go test -short ./...

testfull:
	go test ./...

clean:
	rm -rf bin
