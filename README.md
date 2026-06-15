# portscan

指定ホストの TCP ポートをスキャンして、開放されているポートとそのサービス名を表示する CLI ツールです。TUI 表示に bubbletea、mDNS(Bonjour) 探索に miekg/dns を利用しています。

## 概要

- 任意のホスト・ポート範囲・並列数・タイムアウトをフラグで指定可能
- worker pool による並列スキャン（デフォルト 100 並列）
- `Ctrl-C` (SIGINT) でスキャンを中断可能
- ポート状態（`open` / `filtered`）と推定サービス名を表示
- 出力フォーマットを `text` / `json` / `csv` から選択可能
- 結果は標準出力、進捗・サマリは標準エラー出力に分離（パイプ連携しやすい）
- `-tui` でインタラクティブ画面（リアルタイム進捗バー＋検出ポートの逐次表示）
- 開放ポートに既知リスクがあれば、深刻度・代表攻撃・対策を**常に併記**（防御目的）
- `-banner` で開放ポートのバナーを取得し、サービス/バージョンを推定（HTTP/TLS 対応）
- 開放ポートの顔ぶれとバナーから OS を軽量推定し、確度付きで**常に併記**（root 不要）
- `-mdns` で同一セグメントのホスト名・デバイスモデルを mDNS(Bonjour) 収集（`-discover` では自動有効）
- よく使うスキャン設定を JSON で保存・読込（`-config` / `-save-config`。フラグで上書き可能）

## 必要環境

- Go 1.21 以上

## ビルド

```bash
make build       # Makefile を使う場合（推奨）
go build -o portscan .  # 直接ビルドする場合
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
| `-banner` | 開放ポートのバナーを取得しサービス/バージョンを推定 | `false` |
| `-discover` | 同一セグメントの生存ホストを探索してスキャン | `false` |
| `-cidr` | 探索するサブネット (例 `192.168.1.0/24`)。未指定で自動検出 | （自動） |
| `-tui` | インタラクティブな TUI 画面でスキャン（単一ホスト専用） | `false` |
| `-mdns` | mDNS(Bonjour) でホスト名・デバイスモデルを収集して併記（`-discover` では自動有効） | `false` |
| `-config` | 設定ファイル(JSON)のパス。未指定なら自動探索 | （自動） |
| `-save-config` | 現在の実効設定を指定パスへ JSON で書き出す | （無効） |

### TUI モード

`-tui` を付けると、bubbletea によるインタラクティブ画面でスキャンする。

- グラデーションの**進捗バー**が `scanned/total` に応じてリアルタイム更新
- 開放ポートを**見つけた端から**画面に追記（番号昇順で整列表示）
- `q` / `Esc` / `Ctrl-C` でいつでも中断（スキャンを止めてから終了）
- `-mdns` を併用すると、スキャンと並行で mDNS を収集し、ホスト名と推定 OS を併記する

パイプ連携には向かない表示専用モードなので、`-discover` や `-format` とは併用しない
（複数ホストや機械可読出力が必要なら従来の CLI モードを使う）。

### バナーグラビング

`-banner` を付けると、開放ポートへ接続して**サービスが返すバナー**を取得し、
サービス名やバージョンを推定する。プロトコルごとに取得方法を変える:

- **SSH / FTP / SMTP 等**: 接続直後に送られるバナーをそのまま読む
- **HTTP 系**（80/8080 等）: 簡易リクエストを送り、ステータス行と `Server` ヘッダを取得
- **TLS 系**（443/8443/993 等）: ハンドシェイクして TLS バージョンと証明書 CN を取得（HTTPS は `Server` も）

開放ポートごとに追加の接続が発生するため**やや低速・侵襲的**で、既定は無効。
取得したバナーは各フォーマットに併記される（text はサブ行、JSON は `banner` フィールド、CSV は `banner` 列）。

> バナーは将来の OS 判定（軽量ヒューリスティック）やリスク精度向上の材料にもなる。

### 設定ファイル（JSON）

よく使うスキャン設定を JSON ファイルに保存して使い回せる（標準ライブラリの
encoding/json で読み書き）。

```bash
# いまのフラグ内容を設定ファイルに書き出す
./portscan -host 10.0.0.1 -start 1 -end 1024 -threads 200 -timeout 1s -save-config myscan.json

# 設定ファイルを読み込んでスキャン
./portscan -config myscan.json

# 設定ファイルをベースに、一部だけフラグで上書き（フラグが優先）
./portscan -config myscan.json -host 10.0.0.2
```

- **読み込み順**: `-config` で明示指定 → 無指定なら `./portscan.json` → `~/.config/portscan/config.json`（macOS は `~/Library/Application Support/portscan/config.json`）を順に自動探索
- **優先順位**: コマンドラインフラグ ＞ 設定ファイル ＞ フラグ既定値。明示的に渡したフラグだけが設定ファイルを上書きする
- **保存**: `-save-config <path>` で実効設定を書き出す（そのままスキャンも継続）。`timeout` は `"2s"` のような読みやすい文字列で保存される
- 設定ファイルに**未知のキー**があるとエラーになる（typo を黙って無視しない）

設定ファイルの例:

```json
{
  "host": "10.0.0.1",
  "start": 1,
  "end": 1024,
  "threads": 200,
  "timeout": "1s",
  "format": "json",
  "banner": true
}
```

### OS 推定（軽量ヒューリスティック）

開放ポートの顔ぶれと（取得済みなら）バナー文字列から、対象ホストの OS を
軽量に推定して**常に併記**する。root 権限や生パケット送出は不要で、スキャン結果
だけを材料にする。

- **バナーの OS 名**が最も強い手がかり（例: `Apache/2.4 (Ubuntu)` → Linux (Ubuntu)、確度 high）
- バナーが無ければ**開放ポートのプロファイル**で推定（例: 445/3389/139/135 → Windows、548 → macOS、22 のみ → Linux/Unix）
- 確度は `high` / `medium` / `low` の3段階。`-banner` を併用すると手がかりが増えて精度が上がる
- text はヘッダ行、JSON は `os` フィールド、CSV は `os` / `os_confidence` 列、TUI はヘッダに併記

> 確実な OS フィンガープリンティング（TCP/IP スタック解析等）は行わない。
> あくまで「開いているポートとバナー」からの推測であり、確度で限界を明示している。

### mDNS（Bonjour）でのホスト名・デバイス検出

`-mdns` を付けると、同一セグメントへ mDNS(Bonjour) 問い合わせを投げ、応答した
ホストの**ホスト名（`xxx.local`）とデバイスモデル**（例: `Macmini9,1`）を収集して
スキャン結果に併記する。`-discover` モードでは指定なしでも自動的に併用する。

```bash
# 単一ホストのスキャンにホスト名・モデルを添える
./portscan -host 192.168.1.10 -mdns

# ディスカバリでは自動でホスト名・モデルが付く
./portscan -discover
```

- `_services._dns-sd._udp.local` と `_device-info._tcp.local` を一括問い合わせし、
  応答パケットの**送信元 IP をキー**にホスト名・モデルを対応づける（SRV 追跡は不要）
- Apple 製品のモデルコードは OS 推定にも使う（`Macmini9,1` → macOS / `iPhone15,2` → iOS、確度 high）
- text はヘッダ行（`ホスト名: ...`）、JSON は `hostname` フィールド、CSV は `hostname` 列に出る
- `-tui` と併用すると TUI 画面にもホスト名・推定 OS が併記される（収集中は「mDNS 収集中…」表示）
- mDNS は**リンクローカルマルチキャスト**（224.0.0.251:5353）なのでルーターを越えない
  ＝同一 L2 セグメント限定。応答が無くてもスキャン本体は妨げない（best-effort）

> DNS ワイヤーフォーマット解析には [miekg/dns](https://github.com/miekg/dns) を利用している。

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
      ⚠ [medium] SSH。暗号化されるが総当たり・鍵管理不備が狙われる
        攻撃: パスワード総当たり / 古い実装の既知脆弱性 / 弱い鍵・流出鍵の悪用
        対策: 公開鍵認証のみにしパスワード認証を無効化 / fail2ban 等で試行制限 / アクセス元 IP を制限
 6379 [open]  -->   Redis
      ⚠ [critical] Redis。既定で無認証。公開は即データ窃取・RCE
        攻撃: 無認証アクセスによるデータ窃取・改ざん / CONFIG 悪用による RCE・SSH 鍵書き込み
        対策: requirepass で認証必須化 / bind を localhost に限定し外部公開を遮断 / protected-mode を有効化
```

### 脆弱性・攻撃の注記（リスク DB）

開放ポートに既知のリスクがある場合、各出力フォーマットへ**深刻度・想定攻撃・対策**を
常に併記する。スキャン結果から「次に何を確認・対処すべきか」へ繋げるための防御目的の機能。

- 深刻度は `critical` / `high` / `medium` / `low` の4段階（TUI では色付きバッジ）
- JSON では各ポートに `risk` フィールド、CSV では `severity` / `risk` / `attacks` / `mitigations` 列が付く
- 組み込み静的 DB（50 ポート超）で対応。実際の脆弱性有無はバージョン・構成依存のため、
  本機能は「**注意を促す**」までを担い、確定的な脆弱性診断は行わない

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
    │   ├── banner.go            # 開放ポートのバナー取得（self-announced / HTTP / TLS）
    │   ├── service.go           # ポート番号 → サービス名マッピング
    │   ├── banner_test.go       # バナー取得のテスト
    │   └── scanner_test.go      # テスト・ベンチマーク
    ├── discover/
    │   ├── discover.go          # サブネット列挙＋TCPピングによる生存ホスト探索
    │   └── discover_test.go     # テスト
    ├── report/
    │   ├── report.go            # text / json / csv レンダラ（リスク情報を結合）
    │   └── report_test.go       # テスト
    ├── risk/
    │   ├── risk.go              # 開放ポート→既知リスク・攻撃・対策の組み込みDB
    │   └── risk_test.go         # テスト
    ├── osdetect/
    │   ├── osdetect.go          # 開放ポート＋バナーからの軽量 OS 推定
    │   └── osdetect_test.go     # テスト
    ├── config/
    │   ├── config.go            # スキャン設定の JSON 保存・読込（フラグ優先のマージ）
    │   └── config_test.go       # テスト
    ├── mdns/
    │   ├── mdns.go              # mDNS(Bonjour) でホスト名・デバイスモデルを収集
    │   └── mdns_test.go         # テスト
    └── tui/
        ├── tui.go               # bubbletea によるインタラクティブ画面
        └── tui_test.go          # Model-Update-View のロジックテスト
```

外部依存は TUI 表示の [bubbletea](https://github.com/charmbracelet/bubbletea) 系と、
mDNS 探索の [miekg/dns](https://github.com/miekg/dns) のみ。
`scanner.ScanStream` がスキャンイベントを逐次チャネルへ流し、`tui` がそれを購読して描画する。
リスク情報は `risk.Lookup`、OS 推定は `osdetect.Detect` を `report` / `tui` が描画時に引いて結合する。

## テスト

```bash
make test        # go test ./...
make bench       # 並列スキャンのベンチマーク

# Makefile 不使用の場合
go test ./...
go test -bench=. ./internal/scanner/
```
