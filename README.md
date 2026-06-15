# portscan

localhost のポートをスキャンして、開放されているポートとそのサービス名を表示する CLI ツールです。

## 概要

- スキャン対象: `localhost` (127.0.0.1)
- スキャン範囲: ポート 20〜10000
- 並列スレッド数: 5
- タイムアウト: ポートあたり 2 秒
- 開放ポートのサービス名（HTTP、SSH 等）を合わせて表示

## 必要環境

- Go 1.15 以上

## ビルド

```bash
go build -o portscan .
```

または依存関係を取得してからビルド:

```bash
go mod download
go build -o portscan .
```

## 実行

```bash
./portscan
```

出力例:

```
scanning port 20-10000...
 22 [open]  -->   SSH Remote Login Protocol
 80 [open]  -->   HTTP
 443 [open]  -->   HTTPS
```

## 依存ライブラリ

- [github.com/anvie/port-scanner](https://github.com/anvie/port-scanner)
