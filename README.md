# portscan

指定ホストの TCP ポートをスキャンして、開放されているポートとそのサービス名を表示する CLI ツールです。標準ライブラリのみで実装されており、外部依存はありません。

## 概要

- 任意のホスト・ポート範囲・並列数・タイムアウトをフラグで指定可能
- worker pool による並列スキャン（デフォルト 100 並列）
- `Ctrl-C` (SIGINT) でスキャンを中断可能
- 開放ポートのサービス名（HTTP、SSH 等）を合わせて表示

## 必要環境

- Go 1.21 以上

## ビルド

```bash
go build -o portscan .
```

## 実行

デフォルト（localhost のポート 20〜10000）:

```bash
./portscan
```

オプション指定:

```bash
./portscan -host 192.168.1.1 -start 1 -end 1024 -threads 200 -timeout 1s
```

### フラグ一覧

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `-host` | スキャン対象ホスト | `localhost` |
| `-start` | 開始ポート | `20` |
| `-end` | 終了ポート | `10000` |
| `-threads` | 並列ワーカー数 | `100` |
| `-timeout` | ポートあたりの接続タイムアウト | `2s` |

出力例:

```
scanning localhost port 20-10000...
 22 [open]  -->   SSH
 80 [open]  -->   HTTP
 443 [open]  -->   HTTPS
3 個の開放ポートが見つかりました
```

## 構成

```
.
├── main.go                      # CLI エントリポイント（フラグ解析・出力）
└── internal/scanner/
    ├── scanner.go               # スキャン中核ロジック（net.Dialer + worker pool）
    ├── service.go               # ポート番号 → サービス名マッピング
    └── scanner_test.go          # テスト
```

## テスト

```bash
go test ./...
```
