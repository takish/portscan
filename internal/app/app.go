// Package app はコマンドライン解析後の実行フロー（オーケストレーション）を担う。
//
// 単一ホストスキャン・ディスカバリといった「スキャン → mDNS 結合 → 出力」の
// 制御フローを main から切り離し、出力先を io.Writer で注入可能にすることで
// テスト可能にしている。失敗は os.Exit ではなく error 返却で表現し、終了コードの
// 決定は呼び出し側（main）に委ねる。
package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/takish/portscan/internal/discover"
	"github.com/takish/portscan/internal/mdns"
	"github.com/takish/portscan/internal/report"
	"github.com/takish/portscan/internal/scanner"
)

// mdnsTimeout は mDNS 応答の待ち受け時間。ポートスキャンの Timeout とは
// 別物（あちらは短く設定されがちで応答取りこぼしになる）なので固定値にする。
const mdnsTimeout = 2 * time.Second

// Options は解析済みのコマンドライン設定をまとめる。
type Options struct {
	Cfg      scanner.Config
	Format   report.Format
	Discover bool
	CIDR     string
	TUI      bool
	Mdns     bool
}

// RunSingle は単一ホストのポートスキャンを実行し、結果を stdout へ書く。
// 進捗・サマリは stderr へ出し、パイプ連携を妨げない。
func RunSingle(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	cfg := opts.Cfg
	fmt.Fprintf(stderr, "scanning %s port %d-%d...\n", cfg.Host, cfg.PortStart, cfg.PortEnd)

	// -mdns 指定時はスキャンと並行で mDNS 収集を走らせ、待ち時間を隠す。
	var mdnsCh <-chan map[string]mdns.Entry
	if opts.Mdns {
		mdnsCh = startMDNS(ctx, stderr)
	}

	results, err := scanner.Scan(ctx, cfg)
	if err != nil {
		return fmt.Errorf("スキャン失敗: %w", err)
	}

	// mDNS の結果が出揃ってからホスト名・モデルを結合する（任意機能）。
	var meta report.Meta
	if mdnsCh != nil {
		meta = metaForHost(<-mdnsCh, cfg.Host)
	}

	if err := report.RenderWithMeta(stdout, results, opts.Format, meta); err != nil {
		return fmt.Errorf("出力失敗: %w", err)
	}
	fmt.Fprintf(stderr, "%d 個のポートを検出しました\n", len(results))
	return nil
}

// RunDiscover は同一セグメントの生存ホストを探索し、各ホストをポートスキャンする。
func RunDiscover(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	cidr := opts.CIDR
	if cidr == "" {
		c, err := discover.LocalCIDR()
		if err != nil {
			return fmt.Errorf("サブネット自動検出に失敗: %w（-cidr で指定してください）", err)
		}
		cidr = c
	}

	fmt.Fprintf(stderr, "discovering live hosts in %s ...\n", cidr)
	live, err := discover.Discover(ctx, cidr, opts.Cfg.Threads, opts.Cfg.Timeout)
	if err != nil {
		return fmt.Errorf("ホスト探索失敗: %w", err)
	}
	fmt.Fprintf(stderr, "%d 台の生存ホストを検出。各ホストをスキャンします...\n", len(live))

	// ディスカバリでは mDNS を自動併用する。各ホストのスキャンと並行で収集し、
	// 結果は全ホストのスキャン完了後にまとめてホスト名・モデルへ結合する。
	mdnsCh := startMDNS(ctx, stderr)

	var scans []report.HostScan
	for i, host := range live {
		// 直列スキャンで無反応に見えないよう、何台目を処理中か逐次表示する。
		fmt.Fprintf(stderr, "[%d/%d] %s をスキャン中...\n", i+1, len(live), host)
		cfg := opts.Cfg
		cfg.Host = host
		results, err := scanner.Scan(ctx, cfg)
		if err != nil {
			// キャンセル時は中断、それ以外は当該ホストを飛ばして続行。
			if ctx.Err() != nil {
				fmt.Fprintln(stderr, "中断しました:", err)
				break
			}
			fmt.Fprintf(stderr, "  %s のスキャンに失敗: %v（スキップ）\n", host, err)
			continue
		}
		fmt.Fprintf(stderr, "  %d 個の開放ポートを検出\n", len(results))
		scans = append(scans, report.HostScan{Host: host, Results: results})
	}

	// 並行実行していた mDNS 結果を待ち受け、各ホストへホスト名・モデルを添える。
	entries := <-mdnsCh
	for i := range scans {
		scans[i].Meta = metaForHost(entries, scans[i].Host)
	}

	if err := report.RenderHostScans(stdout, scans, opts.Format); err != nil {
		return fmt.Errorf("出力失敗: %w", err)
	}
	return nil
}

// startMDNS は mDNS 収集をバックグラウンドで開始し、結果を受け取るチャネルを返す。
// mDNS は応答待ちで mdnsTimeout 分ブロックするため、ポートスキャンと並行させて
// 待ち時間を隠す。失敗しても補助機能なのでエラーにせず nil を流して続行する。
func startMDNS(ctx context.Context, stderr io.Writer) <-chan map[string]mdns.Entry {
	ch := make(chan map[string]mdns.Entry, 1)
	fmt.Fprintf(stderr, "mDNS でホスト名・デバイス情報を収集中（最大 %s、スキャンと並行）...\n", mdnsTimeout)
	go func() {
		entries, err := mdns.Browse(ctx, mdnsTimeout)
		if err != nil {
			fmt.Fprintln(stderr, "  mDNS 収集に失敗（無視して続行）:", err)
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
