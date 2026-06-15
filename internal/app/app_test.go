package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/takish/portscan/internal/mdns"
	"github.com/takish/portscan/internal/report"
	"github.com/takish/portscan/internal/scanner"
)

func TestMetaForHost(t *testing.T) {
	entries := map[string]mdns.Entry{
		"192.168.1.5": {Host: "Mac.local", Model: "Macmini9,1"},
	}

	// IP キーでヒットしたら Hostname・Model が詰まる。
	m := metaForHost(entries, "192.168.1.5")
	if m.Hostname != "Mac.local" || m.Model != "Macmini9,1" {
		t.Errorf("ヒット時の Meta が誤り: %+v", m)
	}

	// 該当なしは空 Meta（ゼロ値）を返す。
	if m := metaForHost(entries, "10.0.0.1"); m.Hostname != "" || m.Model != "" {
		t.Errorf("該当なしで空 Meta にならない: %+v", m)
	}

	// 空マップでも安全に空 Meta を返す。
	if m := metaForHost(nil, "192.168.1.5"); m.Hostname != "" || m.Model != "" {
		t.Errorf("空マップで空 Meta にならない: %+v", m)
	}
}

func TestRunSingle_WritesResultToStdout(t *testing.T) {
	// JSON 形式なら開放ポートが無くてもオブジェクトが必ず出力されるため、
	// 「結果が stdout へ書かれる」ことを環境非依存に検証できる。
	format, err := report.ParseFormat("json")
	if err != nil {
		t.Fatal(err)
	}
	// localhost をごく狭いポート範囲で走らせる（mDNS なし＝実ネットワーク非依存）。
	opts := Options{
		Cfg: scanner.Config{
			Host:      "127.0.0.1",
			PortStart: 1,
			PortEnd:   1,
			Threads:   1,
			Timeout:   200 * time.Millisecond,
		},
		Format: format,
	}

	var stdout, stderr bytes.Buffer
	if err := RunSingle(context.Background(), opts, &stdout, &stderr); err != nil {
		t.Fatalf("RunSingle が失敗: %v", err)
	}

	// 進捗は stderr、結果本体は stdout、という分離を検証する。
	if !strings.Contains(stderr.String(), "scanning 127.0.0.1") {
		t.Errorf("stderr に進捗が出ていない:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "個のポートを検出") {
		t.Errorf("stderr にサマリが出ていない:\n%s", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("stdout にレポートが書かれていない")
	}
}

func TestRunDiscover_InvalidCIDRReturnsError(t *testing.T) {
	opts := Options{
		CIDR: "not-a-cidr",
		Cfg:  scanner.Config{Threads: 1, Timeout: time.Second},
	}

	var stdout, stderr bytes.Buffer
	err := RunDiscover(context.Background(), opts, &stdout, &stderr)
	if err == nil {
		t.Fatal("無効な CIDR でエラーを返すべき")
	}
	// os.Exit ではなく error 返却に変えた狙い（テスト可能性）を担保する。
	if stdout.Len() != 0 {
		t.Errorf("エラー時に stdout へ出力してはいけない:\n%s", stdout.String())
	}
}
