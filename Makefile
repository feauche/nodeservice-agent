VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-all test vet clean

## Локальная сборка (текущая ОС) → dist/nodeservice-agent
build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nodeservice-agent .

## Релизные бинари linux/amd64 + linux/arm64 → dist/ + checksums.txt
build-all: clean
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nodeservice-agent_linux_amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/nodeservice-agent_linux_arm64 .
	cd dist && (sha256sum nodeservice-agent_linux_* 2>/dev/null || shasum -a 256 nodeservice-agent_linux_*) > checksums.txt

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist
