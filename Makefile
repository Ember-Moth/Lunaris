.PHONY: install web build dev check test clean

# The management API uses encoding/json for stable Go toolchain compatibility.
GO_BUILD_TAGS ?= stdjson

install:
	pnpm --dir web install --frozen-lockfile
	go mod download

web:
	pnpm --dir web build

build: web
	go build -tags '$(GO_BUILD_TAGS)' -trimpath -o bin/lunaris .

dev: web
	go run -tags '$(GO_BUILD_TAGS)' . serve

check: web
	pnpm --dir web lint
	sh scripts/check-modules.sh
	go vet -tags '$(GO_BUILD_TAGS)' ./...
	go test -tags '$(GO_BUILD_TAGS)' -race ./...

test: web
	go test -tags '$(GO_BUILD_TAGS)' ./...

clean:
	rm -rf bin web/dist
