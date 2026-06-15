package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/takish/portscan/internal/app"
	"github.com/takish/portscan/internal/config"
	"github.com/takish/portscan/internal/report"
	"github.com/takish/portscan/internal/scanner"
	"github.com/takish/portscan/internal/tui"
)

func main() {
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		// -h / --help は正常動作なので、エラー文言なしで終了コード0で抜ける。
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(2)
	}

	// Ctrl-C (SIGINT) で処理を中断できるようにする。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if opts.TUI {
		// TUI は単一ホスト専用。中断は画面内の q / Ctrl-C で行う。
		// -mdns 指定時はスキャンと並行で mDNS を収集しホスト名等を併記する。
		if err := tui.Run(ctx, opts.Cfg, opts.Mdns, opts.OSFingerprint); err != nil {
			fmt.Fprintln(os.Stderr, "TUI 失敗:", err)
			os.Exit(1)
		}
		return
	}

	// スキャン本体は app パッケージへ委譲。出力先を渡し、失敗は error で受ける。
	run := app.RunSingle
	if opts.Discover {
		run = app.RunDiscover
	}
	if err := run(ctx, opts, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(1)
	}
}

// snapshot は実効設定値を config.Config に詰める（-save-config 用）。
// timeout は人間が読みやすいよう duration 文字列（"2s" 等）で保存する。
func snapshot(host string, start, end, threads int, timeout time.Duration, format string, showFiltered, banner, discover bool, cidr string, tui, mdns, osFingerprint bool) config.Config {
	timeoutStr := timeout.String()
	return config.Config{
		Host:          &host,
		Start:         &start,
		End:           &end,
		Threads:       &threads,
		Timeout:       &timeoutStr,
		Format:        &format,
		ShowFiltered:  &showFiltered,
		Banner:        &banner,
		Discover:      &discover,
		CIDR:          &cidr,
		TUI:           &tui,
		Mdns:          &mdns,
		OSFingerprint: &osFingerprint,
	}
}

// parseFlags はコマンドライン引数を解析して options を組み立てる。
func parseFlags(args []string) (app.Options, error) {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)

	host := fs.String("host", "localhost", "スキャン対象ホスト（-discover 指定時は無視）")
	start := fs.Int("start", 20, "開始ポート")
	end := fs.Int("end", 10000, "終了ポート")
	threads := fs.Int("threads", 100, "並列ワーカー数")
	timeout := fs.Duration("timeout", 2*time.Second, "ポートあたりの接続タイムアウト")
	formatStr := fs.String("format", "text", "出力形式 (text/json/csv)")
	showFiltered := fs.Bool("show-filtered", false, "filtered（タイムアウト）ポートも表示する")
	banner := fs.Bool("banner", false, "開放ポートのバナーを取得しサービス/バージョンを推定する（低速・やや侵襲的）")
	discoverMode := fs.Bool("discover", false, "同一セグメントの生存ホストを探索してスキャンする")
	cidr := fs.String("cidr", "", "探索するサブネット (例: 192.168.1.0/24)。未指定なら自動検出")
	tuiMode := fs.Bool("tui", false, "インタラクティブな TUI 画面でスキャンする（単一ホスト専用）")
	mdnsMode := fs.Bool("mdns", false, "mDNS(Bonjour) でホスト名・デバイスモデルを収集して併記する（同一セグメント限定。-discover では自動有効）")
	osFingerprint := fs.Bool("os-fingerprint", false, "ICMP echo の応答 TTL から OS 系統を推定して併記する（root 不要。ICMP 不通先では無効）")
	configPath := fs.String("config", "", "設定ファイル(JSON)のパス。未指定なら ./portscan.json 等を自動探索")
	saveConfigPath := fs.String("save-config", "", "現在の実効設定を指定パスへ JSON で書き出す")

	if err := fs.Parse(args); err != nil {
		return app.Options{}, err
	}

	// 設定ファイルを読み込み、明示指定されていないフラグにのみ適用する。
	// 優先順位は「コマンドラインフラグ ＞ 設定ファイル ＞ フラグ既定値」。
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	cfgFile, srcPath, err := config.Load(*configPath)
	if err != nil {
		return app.Options{}, err
	}
	if err := cfgFile.ApplyTo(fs, explicit); err != nil {
		return app.Options{}, err
	}
	if srcPath != "" {
		fmt.Fprintf(os.Stderr, "設定ファイルを読み込みました: %s\n", srcPath)
	}

	// 実効設定の書き出しが要求されていれば保存する（スキャンは継続する）。
	if *saveConfigPath != "" {
		if err := config.Save(*saveConfigPath, snapshot(*host, *start, *end, *threads, *timeout, *formatStr, *showFiltered, *banner, *discoverMode, *cidr, *tuiMode, *mdnsMode, *osFingerprint)); err != nil {
			return app.Options{}, err
		}
		fmt.Fprintf(os.Stderr, "設定を書き出しました: %s\n", *saveConfigPath)
	}

	// TUI は画面表示専用で、複数ホストのグループ出力とは両立しない。
	if *tuiMode && *discoverMode {
		return app.Options{}, fmt.Errorf("-tui と -discover は同時に指定できません")
	}

	format, err := report.ParseFormat(*formatStr)
	if err != nil {
		return app.Options{}, err
	}

	return app.Options{
		Cfg: scanner.Config{
			Host:            *host,
			PortStart:       *start,
			PortEnd:         *end,
			Threads:         *threads,
			Timeout:         *timeout,
			IncludeFiltered: *showFiltered,
			GrabBanner:      *banner,
		},
		Format:        format,
		Discover:      *discoverMode,
		CIDR:          *cidr,
		TUI:           *tuiMode,
		Mdns:          *mdnsMode,
		OSFingerprint: *osFingerprint,
	}, nil
}
