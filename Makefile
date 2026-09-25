VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath

.PHONY: build test vet dist clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o formd ./cmd/formd

test:
	go test -race ./...

vet:
	go vet ./...

dist:
	mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/formd-linux-$$arch ./cmd/formd; \
	done
	cd dist && shasum -a 256 formd-* > SHA256SUMS

clean:
	rm -rf formd dist
