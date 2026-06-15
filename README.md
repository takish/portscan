# portscan

指定ホストの TCP ポートをスキャンして、開放されているポートとそのサービス名を表示する CLI ツールです。スキャン中核は標準ライブラリのみで実装しています（TUI 表示のみ bubbletea に依存）。

## 概要

- 任意のホスト・ポート範囲・並列数・タイムアウトをフラグで指定可能
- worker pool による並列スキャン（デフォルト 100 並列）
- `Ctrl-C` (SIGINT) でスキャンを中断可能
- ポート状態（`open` / `filtered`）と推定サービス名を表示
- 出力フォーマットを `text` / `json` / `csv` から選択可能
- 結果は標準出力、進捗・サマリは標準エラー出力に分離（パイプ連携しやすい）
- `-tui` でインタラクティブ画面（リアルタイム進捗バー＋検出ポートの逐次表示）

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

インタラクティブな TUI 画面でスキャン（進捗バーがリアルタイム更新、開放ポートが見つかった端から表示）:

```bash
./portscan -tui -host 192.168.1.1 -start 1 -end 1024
```

同一セグメントの生存ホストを探索してまとめてスキャン（ホストディスカバリ）:

```bash
# サブネットを自動検出して探索 → 各生存ホストをスキャン
./portscan -discover

# サブネットを明示し、短いタイムアウトで高速に
./portscan -discover -cidr 192.168.1.0/24 -timeout 500ms -threads 256
```

### フラグ一覧

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `-host` | スキャン対象ホスト（`-discover` 時は無視） | `localhost` |
| `-start` | 開始ポート | `20` |
| `-end` | 終了ポート | `10000` |
| `-threads` | 並列ワーカー数（上限） | `100` |
| `-timeout` | ポートあたりの接続タイムアウト | `2s` |
| `-format` | 出力形式 (`text` / `json` / `csv`) | `text` |
| `-show-filtered` | filtered（タイムアウト）ポートも表示 | `false` |
| `-discover` | 同一セグメントの生存ホストを探索してスキャン | `false` |
| `-cidr` | 探索するサブネット (例 `192.168.1.0/24`)。未指定で自動検出 | （自動） |
| `-tui` | インタラクティブな TUI 画面でスキャン（単一ホスト専用） | `false` |

### TUI モード

`-tui` を付けると、bubbletea によるインタラクティブ画面でスキャンする。

- グラデーションの**進捗バー**が `scanned/total` に応じてリアルタイム更新
- 開放ポートを**見つけた端から**画面に追記（番号昇順で整列表示）
- `q` / `Esc` / `Ctrl-C` でいつでも中断（スキャンを止めてから終了）

パイプ連携には向かない表示専用モードなので、`-discover` や `-format` とは併用しない
（複数ホストや機械可読出力が必要なら従来の CLI モードを使う）。

### ホストディスカバリ

`-discover` を付けると、サブネット内の各ホストへ代表ポート（80/443/22 等）に
TCP 接続を試み、**接続成功または「接続拒否」が返ったホストを生存**とみなす。
ICMP を使わないため **root 権限は不要**。検出した生存ホストを順にポートスキャンし、
ホストごとにグループ化して出力する。

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
    ├── discover/
    │   ├── discover.go          # サブネット列挙＋TCPピングによる生存ホスト探索
    │   └── discover_test.go     # テスト
    ├── report/
    │   ├── report.go            # text / json / csv レンダラ（単一／複数ホスト）
    │   └── report_test.go       # テスト
    └── tui/
        ├── tui.go               # bubbletea によるインタラクティブ画面
        └── tui_test.go          # Model-Update-View のロジックテスト
```

スキャン中核（`scanner` / `discover` / `report`）は標準ライブラリのみ。外部依存は
TUI 表示に使う [bubbletea](https://github.com/charmbracelet/bubbletea) 系のみで、
`scanner.ScanStream` がスキャンイベントを逐次チャネルへ流し、`tui` がそれを購読して描画する。

## テスト

```bash
go test ./...

# 並列スキャンのベンチマーク
go test -bench=. ./internal/scanner/
```
