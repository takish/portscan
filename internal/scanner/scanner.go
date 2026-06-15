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
	"sync/atomic"
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

// Progress はストリーミングスキャン中に発生する1イベントを表す。
// 1ポートのスキャンが終わるたびに1イベント送られ、報告対象を検出した
// 場合のみ Found が非 nil になる。進捗バー表示と結果の逐次受信を兼ねる。
type Progress struct {
	Scanned int     // これまでにスキャンを終えたポート数（1〜Total）
	Total   int     // スキャン対象ポートの総数
	Found   *Result // 検出した報告対象ポート（無ければ nil）
}

// ScanStream は cfg に従ってポートをスキャンし、進捗イベントを逐次チャネルへ
// 流す。チャネルは全ポート走査後（または ctx キャンセル後）にクローズされる。
// 設定不正は即座にエラーとして返す。呼び出し側はチャネルを最後まで読み切り、
// 必要なら ctx.Err() で中断を判定する。Found は到着順（＝完了順）で、昇順では
// ない点に注意。順序が必要な一括取得には Scan を使う。
func ScanStream(ctx context.Context, cfg Config) (<-chan Progress, error) {
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
	// ワーカー数ぶんバッファを持たせ、受信側が一時的に遅れてもワーカーが
	// ブロックしにくくする（UI のレンダリング待ちでスキャンを止めない）。
	out := make(chan Progress, workers)

	// ワーカー: ports から受け取ったポートを順に接続試行する。
	var wg sync.WaitGroup
	var scanned int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				status := probe(ctx, cfg.Host, port, cfg.Timeout)
				n := atomic.AddInt64(&scanned, 1)
				ev := Progress{Scanned: int(n), Total: nPorts}
				if status == StatusOpen || (status == StatusFiltered && cfg.IncludeFiltered) {
					ev.Found = &Result{Port: port, Status: status, Service: DescribePort(port)}
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
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

	// クローザー: 全ワーカー完了後に out を閉じ、受信ループを終わらせる。
	go func() {
		wg.Wait()
		close(out)
	}()

	return out, nil
}

// Scan は cfg に従ってポートをスキャンし、報告対象のポートを番号の昇順で返す。
// 既定では open のみを返し、cfg.IncludeFiltered が true なら filtered も含める。
// ctx のキャンセルで途中終了でき、その場合は ctx.Err() を返す。
// 内部的には ScanStream を読み切って結果を集約する薄いラッパである。
func Scan(ctx context.Context, cfg Config) ([]Result, error) {
	out, err := ScanStream(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var collected []Result
	for ev := range out {
		if ev.Found != nil {
			collected = append(collected, *ev.Found)
		}
	}

	// キャンセルされていた場合は不完全な結果なのでエラーを返す。
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].Port < collected[j].Port
	})
	return collected, nil
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
