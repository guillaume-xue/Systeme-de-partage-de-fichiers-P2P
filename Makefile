.PHONY: run build clean

run:
	go run ./cmd/client

build:
	go build -o bin/client ./cmd/client

clean:
	rm -rf bin