# portscan - Claude向け開発ガイド

TCP ポートスキャン CLI ツール（Go）。TUI 表示に bubbletea、mDNS に miekg/dns を利用する。

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
main.go                    フラグ解析・モード振り分け（薄い CLI エントリポイント）
internal/
  app/      スキャン実行フロー（単一/ディスカバリ）のオーケストレーション。出力先を io.Writer で注入しテスト可能にする
  scanner/  net.Dialer + worker pool でポートスキャン（banner.go: バナー取得）
  discover/ サブネット列挙 + TCPピングでホスト探索
  report/   text/json/csv レンダラ（リスク・OS推定を結合）
  risk/     開放ポート→深刻度・攻撃・対策の静的 DB
  osdetect/ 開放ポート＋バナー＋mDNSモデルからの軽量 OS 推定（確度付き）
  config/   スキャン設定の JSON 保存・読込（フラグ優先でマージ）
  mdns/     mDNS(Bonjour) でホスト名・デバイスモデルを収集（miekg/dns）
  tui/      bubbletea による TUI モード
```

- `scanner.ScanStream` → チャネルでイベントを流す
- `tui` がそのチャネルを購読して描画
- `risk.Lookup` / `osdetect.Detect`（mDNS 併用時は `DetectWithHints`）を `report`/`tui` が描画時に呼び出し
- mDNS は応答パケットの送信元 IP をキーに `report.Meta`（ホスト名・モデル）へ畳み込む

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
| `-mdns` | false | mDNS でホスト名・デバイスモデルを収集（`-discover` では自動有効） |
| `-config` | 自動 | 設定ファイル(JSON)のパス。未指定なら自動探索 |
| `-save-config` | 無効 | 実効設定を JSON で書き出す |

## 制約

- `-tui` と `-discover` は同時指定不可
- 依存ライブラリは必要に応じて追加してよい（旧 dependency-zero 方針は廃止）。ただし追加時は目的をコミット/PR に明記し、軽量で保守されているものを選ぶ
- 単一ホストの JSON 出力は `{ "hostname": "...", "os": {...}, "ports": [...] }` のオブジェクト（ホスト名・OS推定がホスト単位のため。hostname は mDNS 取得時のみ）
- `-discover` は mDNS を自動併用。`-tui` でも `-mdns` 指定時はスキャンと並行で mDNS 収集しホスト名・モデルを併記する
- 設定の優先順位は「コマンドラインフラグ ＞ 設定ファイル ＞ フラグ既定値」。`flag.Visit` で明示指定フラグを検出して上書き判定する
- 進捗・サマリは stderr、スキャン結果は stdout（パイプ連携のため）
