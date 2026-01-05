.PHONY: all run build clean windows

all: clean build run

run:
	./bin/client

build:
	go build -o bin/client ./cmd/client

clean:
	rm -rf bin

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/client.exe ./cmd/client
