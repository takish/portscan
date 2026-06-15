package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/takish/portscan/internal/report"
	"github.com/takish/portscan/internal/scanner"
)

func main() {
	cfg, format, err := parseFlags(os.Args[1:])
	if err != nil {
		// -h / --help は正常動作なので、エラー文言なしで終了コード0で抜ける。
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(2)
	}

	// Ctrl-C (SIGINT) でスキャンを中断できるようにする。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// 進捗・サマリは stderr へ。結果本体は stdout へ出し、パイプ連携を妨げない。
	fmt.Fprintf(os.Stderr, "scanning %s port %d-%d...\n", cfg.Host, cfg.PortStart, cfg.PortEnd)

	results, err := scanner.Scan(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "スキャン失敗:", err)
		os.Exit(1)
	}

	if err := report.Render(os.Stdout, results, format); err != nil {
		fmt.Fprintln(os.Stderr, "出力失敗:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "%d 個のポートを検出しました\n", len(results))
}

// parseFlags はコマンドライン引数を解析して Config と出力フォーマットを組み立てる。
func parseFlags(args []string) (scanner.Config, report.Format, error) {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)

	host := fs.String("host", "localhost", "スキャン対象ホスト")
	start := fs.Int("start", 20, "開始ポート")
	end := fs.Int("end", 10000, "終了ポート")
	threads := fs.Int("threads", 100, "並列ワーカー数")
	timeout := fs.Duration("timeout", 2*time.Second, "ポートあたりの接続タイムアウト")
	formatStr := fs.String("format", "text", "出力形式 (text/json/csv)")
	showFiltered := fs.Bool("show-filtered", false, "filtered（タイムアウト）ポートも表示する")

	if err := fs.Parse(args); err != nil {
		return scanner.Config{}, "", err
	}

	format, err := report.ParseFormat(*formatStr)
	if err != nil {
		return scanner.Config{}, "", err
	}

	cfg := scanner.Config{
		Host:            *host,
		PortStart:       *start,
		PortEnd:         *end,
		Threads:         *threads,
		Timeout:         *timeout,
		IncludeFiltered: *showFiltered,
	}
	return cfg, format, nil
}
