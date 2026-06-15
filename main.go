package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/takish/portscan/internal/config"
	"github.com/takish/portscan/internal/discover"
	"github.com/takish/portscan/internal/mdns"
	"github.com/takish/portscan/internal/report"
	"github.com/takish/portscan/internal/scanner"
	"github.com/takish/portscan/internal/tui"
)

// mdnsTimeout は mDNS 応答の待ち受け時間。ポートスキャンの -timeout とは
// 別物（あちらは短く設定されがちで応答取りこぼしになる）なので固定値にする。
const mdnsTimeout = 2 * time.Second

// options は解析済みのコマンドライン設定をまとめる。
type options struct {
	cfg      scanner.Config
	format   report.Format
	discover bool
	cidr     string
	tui      bool
	mdns     bool
}

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

	if opts.tui {
		// TUI は単一ホスト専用。中断は画面内の q / Ctrl-C で行う。
		// -mdns 指定時はスキャンと並行で mDNS を収集しホスト名等を併記する。
		if err := tui.Run(ctx, opts.cfg, opts.mdns); err != nil {
			fmt.Fprintln(os.Stderr, "TUI 失敗:", err)
			os.Exit(1)
		}
		return
	}

	if opts.discover {
		runDiscover(ctx, opts)
		return
	}
	runSingle(ctx, opts)
}

// runSingle は単一ホストのポートスキャンを実行する。
func runSingle(ctx context.Context, opts options) {
	cfg := opts.cfg
	// 進捗・サマリは stderr へ。結果本体は stdout へ出し、パイプ連携を妨げない。
	fmt.Fprintf(os.Stderr, "scanning %s port %d-%d...\n", cfg.Host, cfg.PortStart, cfg.PortEnd)

	// -mdns 指定時はスキャンと並行で mDNS 収集を走らせ、待ち時間を隠す。
	var mdnsCh <-chan map[string]mdns.Entry
	if opts.mdns {
		mdnsCh = startMDNS(ctx)
	}

	results, err := scanner.Scan(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "スキャン失敗:", err)
		os.Exit(1)
	}

	// mDNS の結果が出揃ってからホスト名・モデルを結合する（任意機能）。
	var meta report.Meta
	if mdnsCh != nil {
		meta = metaForHost(<-mdnsCh, cfg.Host)
	}

	if err := report.RenderWithMeta(os.Stdout, results, opts.format, meta); err != nil {
		fmt.Fprintln(os.Stderr, "出力失敗:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%d 個のポートを検出しました\n", len(results))
}

// startMDNS は mDNS 収集をバックグラウンドで開始し、結果を受け取るチャネルを返す。
// mDNS は応答待ちで mdnsTimeout 分ブロックするため、ポートスキャンと並行させて
// 待ち時間を隠す。失敗しても補助機能なのでエラーにせず nil を流して続行する。
func startMDNS(ctx context.Context) <-chan map[string]mdns.Entry {
	ch := make(chan map[string]mdns.Entry, 1)
	fmt.Fprintf(os.Stderr, "mDNS でホスト名・デバイス情報を収集中（最大 %s、スキャンと並行）...\n", mdnsTimeout)
	go func() {
		entries, err := mdns.Browse(ctx, mdnsTimeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  mDNS 収集に失敗（無視して続行）:", err)
			ch <- nil
			return
		}
		ch <- entries
	}()
	return ch
}

// metaForHost は host に対応する mDNS 情報を report.Meta へ変換する。
// 照合（IP キー引き・名前解決）は mdns.Lookup に委ねる。
func metaForHost(entries map[string]mdns.Entry, host string) report.Meta {
	if e, ok := mdns.Lookup(entries, host); ok {
		return report.Meta{Hostname: e.Host, Model: e.Model}
	}
	return report.Meta{}
}

// runDiscover は同一セグメントの生存ホストを探索し、各ホストをポートスキャンする。
func runDiscover(ctx context.Context, opts options) {
	cidr := opts.cidr
	if cidr == "" {
		c, err := discover.LocalCIDR()
		if err != nil {
			fmt.Fprintln(os.Stderr, "サブネット自動検出に失敗:", err, "（-cidr で指定してください）")
			os.Exit(1)
		}
		cidr = c
	}

	fmt.Fprintf(os.Stderr, "discovering live hosts in %s ...\n", cidr)
	live, err := discover.Discover(ctx, cidr, opts.cfg.Threads, opts.cfg.Timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ホスト探索失敗:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%d 台の生存ホストを検出。各ホストをスキャンします...\n", len(live))

	// ディスカバリでは mDNS を自動併用する。各ホストのスキャンと並行で収集し、
	// 結果は全ホストのスキャン完了後にまとめてホスト名・モデルへ結合する。
	mdnsCh := startMDNS(ctx)

	var scans []report.HostScan
	for i, host := range live {
		// 直列スキャンで無反応に見えないよう、何台目を処理中か逐次表示する。
		fmt.Fprintf(os.Stderr, "[%d/%d] %s をスキャン中...\n", i+1, len(live), host)
		cfg := opts.cfg
		cfg.Host = host
		results, err := scanner.Scan(ctx, cfg)
		if err != nil {
			// キャンセル時は中断、それ以外は当該ホストを飛ばして続行。
			if ctx.Err() != nil {
				fmt.Fprintln(os.Stderr, "中断しました:", err)
				break
			}
			fmt.Fprintf(os.Stderr, "  %s のスキャンに失敗: %v（スキップ）\n", host, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %d 個の開放ポートを検出\n", len(results))
		scans = append(scans, report.HostScan{Host: host, Results: results})
	}

	// 並行実行していた mDNS 結果を待ち受け、各ホストへホスト名・モデルを添える。
	entries := <-mdnsCh
	for i := range scans {
		scans[i].Meta = metaForHost(entries, scans[i].Host)
	}

	if err := report.RenderHostScans(os.Stdout, scans, opts.format); err != nil {
		fmt.Fprintln(os.Stderr, "出力失敗:", err)
		os.Exit(1)
	}
}

// snapshot は実効設定値を config.Config に詰める（-save-config 用）。
// timeout は人間が読みやすいよう duration 文字列（"2s" 等）で保存する。
func snapshot(host string, start, end, threads int, timeout time.Duration, format string, showFiltered, banner, discover bool, cidr string, tui, mdns bool) config.Config {
	timeoutStr := timeout.String()
	return config.Config{
		Host:         &host,
		Start:        &start,
		End:          &end,
		Threads:      &threads,
		Timeout:      &timeoutStr,
		Format:       &format,
		ShowFiltered: &showFiltered,
		Banner:       &banner,
		Discover:     &discover,
		CIDR:         &cidr,
		TUI:          &tui,
		Mdns:         &mdns,
	}
}

// parseFlags はコマンドライン引数を解析して options を組み立てる。
func parseFlags(args []string) (options, error) {
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
	configPath := fs.String("config", "", "設定ファイル(JSON)のパス。未指定なら ./portscan.json 等を自動探索")
	saveConfigPath := fs.String("save-config", "", "現在の実効設定を指定パスへ JSON で書き出す")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	// 設定ファイルを読み込み、明示指定されていないフラグにのみ適用する。
	// 優先順位は「コマンドラインフラグ ＞ 設定ファイル ＞ フラグ既定値」。
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	cfgFile, srcPath, err := config.Load(*configPath)
	if err != nil {
		return options{}, err
	}
	if err := cfgFile.ApplyTo(fs, explicit); err != nil {
		return options{}, err
	}
	if srcPath != "" {
		fmt.Fprintf(os.Stderr, "設定ファイルを読み込みました: %s\n", srcPath)
	}

	// 実効設定の書き出しが要求されていれば保存する（スキャンは継続する）。
	if *saveConfigPath != "" {
		if err := config.Save(*saveConfigPath, snapshot(*host, *start, *end, *threads, *timeout, *formatStr, *showFiltered, *banner, *discoverMode, *cidr, *tuiMode, *mdnsMode)); err != nil {
			return options{}, err
		}
		fmt.Fprintf(os.Stderr, "設定を書き出しました: %s\n", *saveConfigPath)
	}

	// TUI は画面表示専用で、複数ホストのグループ出力とは両立しない。
	if *tuiMode && *discoverMode {
		return options{}, fmt.Errorf("-tui と -discover は同時に指定できません")
	}

	format, err := report.ParseFormat(*formatStr)
	if err != nil {
		return options{}, err
	}

	return options{
		cfg: scanner.Config{
			Host:            *host,
			PortStart:       *start,
			PortEnd:         *end,
			Threads:         *threads,
			Timeout:         *timeout,
			IncludeFiltered: *showFiltered,
			GrabBanner:      *banner,
		},
		format:   format,
		discover: *discoverMode,
		cidr:     *cidr,
		tui:      *tuiMode,
		mdns:     *mdnsMode,
	}, nil
}
