package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

// listen はループバック上で空きポートのリスナーを立て、ポート番号を返す。
// クリーンアップは t.Cleanup に登録する。
func listen(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("リスナー作成に失敗: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScan_FindsOpenPort(t *testing.T) {
	port := listen(t)

	cfg := Config{
		Host:      "127.0.0.1",
		PortStart: port,
		PortEnd:   port,
		Threads:   1,
		Timeout:   time.Second,
	}

	results, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Scan が失敗: %v", err)
	}
	if len(results) != 1 || results[0].Port != port {
		t.Fatalf("開放ポート %d を検出できず: %+v", port, results)
	}
}

func TestScan_ResultsSorted(t *testing.T) {
	p1 := listen(t)
	p2 := listen(t)
	low, high := p1, p2
	if low > high {
		low, high = high, low
	}

	cfg := Config{
		Host:      "127.0.0.1",
		PortStart: low,
		PortEnd:   high,
		Threads:   50,
		Timeout:   time.Second,
	}

	results, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Scan が失敗: %v", err)
	}
	// 並列実行でも結果は昇順で返ること、両ポートが含まれることを確認する。
	var prev int
	gotLow, gotHigh := false, false
	for _, r := range results {
		if r.Port < prev {
			t.Fatalf("結果がソートされていません: %+v", results)
		}
		prev = r.Port
		if r.Port == low {
			gotLow = true
		}
		if r.Port == high {
			gotHigh = true
		}
	}
	if !gotLow || !gotHigh {
		t.Fatalf("両方の開放ポート(%d, %d)が含まれていません: %+v", low, high, results)
	}
}

func TestScan_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 即キャンセル

	cfg := Config{
		Host:      "127.0.0.1",
		PortStart: 20,
		PortEnd:   10000,
		Threads:   10,
		Timeout:   time.Second,
	}

	if _, err := Scan(ctx, cfg); err == nil {
		t.Fatal("キャンセル済み context でエラーが返るべき")
	}
}

func TestConfig_Validate(t *testing.T) {
	base := Config{Host: "localhost", PortStart: 1, PortEnd: 100, Threads: 5, Timeout: time.Second}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"正常", func(c *Config) {}, false},
		{"host空", func(c *Config) { c.Host = "" }, true},
		{"開始ポート範囲外", func(c *Config) { c.PortStart = 0 }, true},
		{"終了ポート範囲外", func(c *Config) { c.PortEnd = 70000 }, true},
		{"開始>終了", func(c *Config) { c.PortStart = 200 }, true},
		{"並列数0", func(c *Config) { c.Threads = 0 }, true},
		{"タイムアウト0", func(c *Config) { c.Timeout = 0 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestDescribePort(t *testing.T) {
	if got := DescribePort(22); got != "SSH" {
		t.Errorf("DescribePort(22)=%q, want SSH", got)
	}
	if got := DescribePort(443); got != "HTTPS" {
		t.Errorf("DescribePort(443)=%q, want HTTPS", got)
	}
	if got := DescribePort(12345); got != "unknown" {
		t.Errorf("DescribePort(12345)=%q, want unknown", got)
	}
}
