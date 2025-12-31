.PHONY: all run build clean

all: clean build run

run:
	./bin/client
build:
	go build -o bin/client ./cmd/client

clean:
	rm -rf bin

diagnose:
	go build -o bin/diagnostic ./cmd/diagnostic
	./bin/diagnostic

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/mon_projet.exe ./cmd/client