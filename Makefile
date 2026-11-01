.PHONY: install install-web web build build-web dev check check-web test clean

# The management API uses encoding/json for stable Go toolchain compatibility.
GO_BUILD_TAGS ?= stdjson

install:
	go mod download

install-web: install
	pnpm --dir web install --frozen-lockfile

web:
	pnpm --dir web build

build:
	go build -tags '$(GO_BUILD_TAGS)' -trimpath -o bin/lunaris .

build-web: web
	go build -tags '$(GO_BUILD_TAGS),webui' -trimpath -o bin/lunaris-web .

dev:
	go run -tags '$(GO_BUILD_TAGS)' . run --config examples/shadowsocks.yaml

check:
	sh scripts/check-modules.sh
	go vet -tags '$(GO_BUILD_TAGS)' ./...
	go test -tags '$(GO_BUILD_TAGS)' -race ./...

check-web: web
	pnpm --dir web lint
	go vet -tags '$(GO_BUILD_TAGS),webui' ./...
	go test -tags '$(GO_BUILD_TAGS),webui' -race ./...

test:
	go test -tags '$(GO_BUILD_TAGS)' ./...

clean:
	rm -rf bin web/dist
