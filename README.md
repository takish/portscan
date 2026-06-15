# portscan

指定ホストの TCP ポートをスキャンして、開放されているポートとそのサービス名を表示する CLI ツールです。標準ライブラリのみで実装されており、外部依存はありません。

## 概要

- 任意のホスト・ポート範囲・並列数・タイムアウトをフラグで指定可能
- worker pool による並列スキャン（デフォルト 100 並列）
- `Ctrl-C` (SIGINT) でスキャンを中断可能
- ポート状態（`open` / `filtered`）と推定サービス名を表示
- 出力フォーマットを `text` / `json` / `csv` から選択可能
- 結果は標準出力、進捗・サマリは標準エラー出力に分離（パイプ連携しやすい）

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

JSON で結果だけをファイルに保存（進捗は画面に残る）:

```bash
./portscan -format json > result.json
```

### フラグ一覧

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `-host` | スキャン対象ホスト | `localhost` |
| `-start` | 開始ポート | `20` |
| `-end` | 終了ポート | `10000` |
| `-threads` | 並列ワーカー数（上限） | `100` |
| `-timeout` | ポートあたりの接続タイムアウト | `2s` |
| `-format` | 出力形式 (`text` / `json` / `csv`) | `text` |
| `-show-filtered` | filtered（タイムアウト）ポートも表示 | `false` |

### ポート状態

| 状態 | 意味 |
|------|------|
| `open` | 接続に成功（ポート開放） |
| `closed` | 接続を拒否された（既定では非表示） |
| `filtered` | タイムアウト（FW 等でドロップされた可能性。`-show-filtered` で表示） |

出力例（text）:

```
 22 [open]  -->   SSH
 80 [open]  -->   HTTP
 443 [open]  -->   HTTPS
```

## パフォーマンス

並列数を上げると、特にリモートホストの無反応ポート（タイムアウト待ちが発生する）で効果が大きい。

localhost で 1001 ポートをスキャンした参考値:

| 並列数 | 所要時間 |
|--------|---------|
| 1 | 0.34s |
| 5 | 0.05s |
| 100 | 0.03s |

リモートでは無反応ポート1つにつき `-timeout` 分だけ待つため、並列化の効果はさらに大きくなる。

## 構成

```
.
├── main.go                      # CLI エントリポイント（フラグ解析・出力振り分け）
└── internal/
    ├── scanner/
    │   ├── scanner.go           # スキャン中核ロジック（net.Dialer + worker pool）
    │   ├── service.go           # ポート番号 → サービス名マッピング
    │   └── scanner_test.go      # テスト・ベンチマーク
    └── report/
        ├── report.go            # text / json / csv レンダラ
        └── report_test.go       # テスト
```

## テスト

```bash
go test ./...

# 並列スキャンのベンチマーク
go test -bench=. ./internal/scanner/
```
