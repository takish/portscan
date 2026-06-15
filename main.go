package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/takish/portscan/internal/scanner"
)

func main() {
	cfg, err := parseFlags(os.Args[1:])
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

	fmt.Printf("scanning %s port %d-%d...\n", cfg.Host, cfg.PortStart, cfg.PortEnd)

	results, err := scanner.Scan(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "スキャン失敗:", err)
		os.Exit(1)
	}

	for _, r := range results {
		fmt.Printf(" %d [open]  -->   %s\n", r.Port, r.Service)
	}
	fmt.Printf("%d 個の開放ポートが見つかりました\n", len(results))
}

// parseFlags はコマンドライン引数を解析して Config を組み立てる。
func parseFlags(args []string) (scanner.Config, error) {
	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)

	host := fs.String("host", "localhost", "スキャン対象ホスト")
	start := fs.Int("start", 20, "開始ポート")
	end := fs.Int("end", 10000, "終了ポート")
	threads := fs.Int("threads", 100, "並列ワーカー数")
	timeout := fs.Duration("timeout", 2*time.Second, "ポートあたりの接続タイムアウト")

	if err := fs.Parse(args); err != nil {
		return scanner.Config{}, err
	}

	return scanner.Config{
		Host:      *host,
		PortStart: *start,
		PortEnd:   *end,
		Threads:   *threads,
		Timeout:   *timeout,
	}, nil
}
