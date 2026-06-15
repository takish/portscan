// Package scanner は TCP ポートスキャンの中核ロジックを提供する。
// 外部ライブラリに依存せず、標準ライブラリの net パッケージのみで実装している。
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Status はポートのスキャン結果の状態を表す。
type Status int

const (
	StatusOpen     Status = iota // 接続に成功した（ポート開放）
	StatusClosed                 // 接続を拒否された（ポート閉鎖、相手は応答）
	StatusFiltered               // タイムアウト（FW等でドロップされた可能性）
)

// String は状態の表示用文字列を返す。
func (s Status) String() string {
	switch s {
	case StatusOpen:
		return "open"
	case StatusClosed:
		return "closed"
	case StatusFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// MarshalJSON は Status を文字列として JSON 出力する。
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON は文字列表現の Status を読み戻す。
func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "open":
		*s = StatusOpen
	case "closed":
		*s = StatusClosed
	case "filtered":
		*s = StatusFiltered
	default:
		return fmt.Errorf("不明な Status: %q", str)
	}
	return nil
}

// Config はスキャンの設定を保持する。
type Config struct {
	Host            string        // スキャン対象ホスト（例: "localhost"）
	PortStart       int           // スキャン開始ポート
	PortEnd         int           // スキャン終了ポート（含む）
	Threads         int           // 並列ワーカー数（上限）
	Timeout         time.Duration // ポート1つあたりの接続タイムアウト
	IncludeFiltered bool          // true の場合、filtered（タイムアウト）ポートも結果に含める
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

// Result は1つのポートのスキャン結果を表す。
type Result struct {
	Port    int    `json:"port"`    // ポート番号
	Status  Status `json:"status"`  // ポートの状態
	Service string `json:"service"` // 推定サービス名（不明な場合は "unknown"）
}

// portResult はワーカーからコレクタへ渡す内部用の結果。
type portResult struct {
	port   int
	status Status
}

// Scan は cfg に従ってポートをスキャンし、報告対象のポートを番号の昇順で返す。
// 既定では open のみを返し、cfg.IncludeFiltered が true なら filtered も含める。
// ctx のキャンセルで途中終了でき、その場合は ctx.Err() を返す。
func Scan(ctx context.Context, cfg Config) ([]Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// S-1: ポート数より多いワーカーを起動しても無駄なので頭打ちにする。
	nPorts := cfg.PortEnd - cfg.PortStart + 1
	workers := cfg.Threads
	if workers > nPorts {
		workers = nPorts
	}

	ports := make(chan int)
	found := make(chan portResult)

	// ワーカー: ports から受け取ったポートを順に接続試行する。
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				status := probe(ctx, cfg.Host, port, cfg.Timeout)
				if status == StatusOpen || (status == StatusFiltered && cfg.IncludeFiltered) {
					found <- portResult{port: port, status: status}
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

	var collected []portResult
	for pr := range found {
		collected = append(collected, pr)
	}

	// キャンセルされていた場合は不完全な結果なのでエラーを返す。
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].port < collected[j].port
	})
	results := make([]Result, len(collected))
	for i, pr := range collected {
		results[i] = Result{Port: pr.port, Status: pr.status, Service: DescribePort(pr.port)}
	}
	return results, nil
}

// probe は host:port へ TCP 接続を試み、状態を判定する。
//   - 接続成功            → StatusOpen
//   - タイムアウト        → StatusFiltered
//   - それ以外（拒否等）  → StatusClosed
func probe(ctx context.Context, host string, port int, timeout time.Duration) Status {
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return StatusOpen
	}
	if isTimeout(err) {
		return StatusFiltered
	}
	return StatusClosed
}

// isTimeout はエラーがネットワークタイムアウトかどうかを判定する。
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
