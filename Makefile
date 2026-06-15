BINARY  := portscan
MODULE  := github.com/takish/portscan
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)

.PHONY: build test bench clean run fmt vet help

## build: バイナリをビルド（./portscan）
build:
	go build -o $(BINARY) .

## test: 全パッケージのユニットテストを実行
test:
	go test ./...

## bench: scanner の並列スキャンベンチマークを実行
bench:
	go test -bench=. -benchmem ./internal/scanner/

## vet: go vet で静的解析
vet:
	go vet ./...

## fmt: gofmt でフォーマット整形
fmt:
	gofmt -w .

## clean: ビルド成果物を削除
clean:
	rm -f $(BINARY)

## run: デフォルト設定でスキャン（localhost:20-10000）
run: build
	./$(BINARY)

## help: このヘルプを表示
help:
	@grep -E '^## ' Makefile | sed 's/## //'
