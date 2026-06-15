// Package scanner は TCP ポートスキャンの中核ロジックを提供する。
// 外部ライブラリに依存せず、標準ライブラリの net パッケージのみで実装している。
package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Config はスキャンの設定を保持する。
type Config struct {
	Host      string        // スキャン対象ホスト（例: "localhost"）
	PortStart int           // スキャン開始ポート
	PortEnd   int           // スキャン終了ポート（含む）
	Threads   int           // 並列ワーカー数
	Timeout   time.Duration // ポート1つあたりの接続タイムアウト
}

// Validate は設定値が妥当かを検証する。
func (c Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("host が指定されていません")
	}
	if c.PortStart < 1 || c.PortStart > 65535 {
		return fmt.Errorf("開始ポートが範囲外です: %d (1-65535)", c.PortStart)
	}
	if c.PortEnd < 1 || c.PortEnd > 65535 {
		return fmt.Errorf("終了ポートが範囲外です: %d (1-65535)", c.PortEnd)
	}
	if c.PortStart > c.PortEnd {
		return fmt.Errorf("開始ポート(%d)が終了ポート(%d)より大きいです", c.PortStart, c.PortEnd)
	}
	if c.Threads < 1 {
		return fmt.Errorf("並列数は1以上が必要です: %d", c.Threads)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("タイムアウトは正の値が必要です: %s", c.Timeout)
	}
	return nil
}

// Result は1つの開放ポートの情報を表す。
type Result struct {
	Port    int    // ポート番号
	Service string // 推定サービス名（不明な場合は "unknown"）
}

// Scan は cfg に従ってポートをスキャンし、開放ポートを番号の昇順で返す。
// ctx のキャンセルで途中終了でき、その場合は ctx.Err() を返す。
func Scan(ctx context.Context, cfg Config) ([]Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ports := make(chan int)
	found := make(chan int)

	// ワーカー: ports から受け取ったポートを順に接続試行する。
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				if isOpen(ctx, cfg.Host, port, cfg.Timeout) {
					found <- port
				}
			}
		}()
	}

	// フィーダー: 全ポートを ports へ流し込む。ctx キャンセルで早期離脱する。
	go func() {
		defer close(ports)
		for p := cfg.PortStart; p <= cfg.PortEnd; p++ {
			select {
			case <-ctx.Done():
				return
			case ports <- p:
			}
		}
	}()

	// クローザー: 全ワーカー完了後に found を閉じ、収集ループを終わらせる。
	go func() {
		wg.Wait()
		close(found)
	}()

	var open []int
	for p := range found {
		open = append(open, p)
	}

	// キャンセルされていた場合は不完全な結果なのでエラーを返す。
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Ints(open)
	results := make([]Result, len(open))
	for i, p := range open {
		results[i] = Result{Port: p, Service: DescribePort(p)}
	}
	return results, nil
}

// isOpen は host:port へ TCP 接続を試み、成功すれば開放とみなす。
func isOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
