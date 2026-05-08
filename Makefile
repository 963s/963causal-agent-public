# Static release binaries (CGO_ENABLED=0) for customer installs / open-source distribution.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
.PHONY: release release-linux-amd64 release-linux-arm64

release-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -buildmode=pie -trimpath \
		-ldflags="-s -w -X main.AgentVersion=$(VERSION)" \
		-o bin/963causal-agent-linux-amd64 ./cmd/963causal-agent

release-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -buildmode=pie -trimpath \
		-ldflags="-s -w -X main.AgentVersion=$(VERSION)" \
		-o bin/963causal-agent-linux-arm64 ./cmd/963causal-agent

release: release-linux-amd64 release-linux-arm64
