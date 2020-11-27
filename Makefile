CWD:=$(shell echo `pwd`)
BUILD_DIR:=$(CWD)/build
BUILD_OS:=`go env GOOS`
BUILD_OS_ARCH:=`go env GOARCH`
BUILD_OS_GOPATH=`go env GOPATH`

.PHONY: build test release

build: compile

fmt:
	gofmt -s -w *.go
	gofmt -s -w */*.go

	goimports -w *.go
	goimports -w */*.go

	go mod tidy

cover: test
	go tool cover -html=./coverage.out

test: lint
	go mod vendor
	go vet ./...
	rm -rf ./coverage.out
	go test -coverpkg=./... -coverprofile=./coverage.out ./...

lint:
	go vet ./...
	staticcheck -f text ./...
	$(exit $(go fmt $EXCLUDE_VENDOR | wc -l))