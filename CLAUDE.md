# portscan - Claude向け開発ガイド

TCP ポートスキャン CLI ツール（Go）。標準ライブラリのみでスキャン中核を実装し、TUI 表示のみ bubbletea に依存する。

## ビルド・テスト

```bash
make build        # バイナリをビルド（./portscan）
make test         # go test ./...
make bench        # scanner ベンチマーク
make clean        # バイナリ削除
go build -o portscan .  # Makefile 不使用の場合
```

## アーキテクチャ

```
main.go                    フラグ解析・モード振り分け（CLI エントリポイント）
internal/
  scanner/  net.Dialer + worker pool でポートスキャン（banner.go: バナー取得）
  discover/ サブネット列挙 + TCPピングでホスト探索
  report/   text/json/csv レンダラ（リスク・OS推定を結合）
  risk/     開放ポート→深刻度・攻撃・対策の静的 DB
  osdetect/ 開放ポート＋バナーからの軽量 OS 推定（確度付き）
  tui/      bubbletea による TUI モード
```

- `scanner.ScanStream` → チャネルでイベントを流す
- `tui` がそのチャネルを購読して描画
- `risk.Lookup` / `osdetect.Detect` を `report`/`tui` が描画時に呼び出し

## 主要フラグ（parseFlags）

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `-host` | localhost | スキャン対象 |
| `-start` / `-end` | 20 / 10000 | ポート範囲 |
| `-threads` | 100 | 並列数 |
| `-timeout` | 2s | 接続タイムアウト |
| `-format` | text | text / json / csv |
| `-show-filtered` | false | タイムアウトポートも表示 |
| `-banner` | false | 開放ポートのバナーを取得しサービス/バージョン推定 |
| `-discover` | false | ホストディスカバリモード |
| `-cidr` | 自動 | サブネット指定 |
| `-tui` | false | TUI インタラクティブモード |

## 制約

- `-tui` と `-discover` は同時指定不可
- スキャン中核（scanner/discover/report/risk/osdetect）は標準ライブラリのみ。外部依存を増やさない
- 単一ホストの JSON 出力は `{ "os": {...}, "ports": [...] }` のオブジェクト（OS推定がホスト単位のため）
- 進捗・サマリは stderr、スキャン結果は stdout（パイプ連携のため）
