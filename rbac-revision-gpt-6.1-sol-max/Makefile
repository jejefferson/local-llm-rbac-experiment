.PHONY: build run test race vet check

export GOTOOLCHAIN := local
export GOPROXY := off
export GOSUMDB := off

build:
	go build -buildvcs=false -o bin/rbac .

run:
	go run -buildvcs=false . -addr 127.0.0.1:8080

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

check: test race vet
