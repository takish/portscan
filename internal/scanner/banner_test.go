package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClip(t *testing.T) {
	if got := clip("SSH-2.0-OpenSSH_8.9\r\nextra"); got != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("複数行の丸めに失敗: %q", got)
	}
	if got := clip("  ab\x00\x07cd  "); got != "abcd" {
		t.Errorf("制御文字除去に失敗: %q", got)
	}
	long := strings.Repeat("x", 400)
	if got := clip(long); len(got) != maxBannerLen {
		t.Errorf("長さ制限に失敗: len=%d, want %d", len(got), maxBannerLen)
	}
}

// bannerListener は接続を受けるたびに banner を書いて閉じるリスナーを立てる。
func bannerListener(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("リスナー作成に失敗: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(banner))
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestGrabBanner_SelfAnnounced(t *testing.T) {
	// SSH/FTP/SMTP のように接続直後にバナーを送るサーバを模す。
	port := bannerListener(t, "SSH-2.0-TestServer\r\n")
	got := grabBanner(context.Background(), "127.0.0.1", port, time.Second)
	if got != "SSH-2.0-TestServer" {
		t.Errorf("grabBanner=%q, want SSH-2.0-TestServer", got)
	}
}

func TestGrabBanner_Unreachable(t *testing.T) {
	// 閉じているポートではバナーは空（エラーにしない）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("リスナー作成に失敗: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if got := grabBanner(context.Background(), "127.0.0.1", port, 300*time.Millisecond); got != "" {
		t.Errorf("到達不能ポートで非空: %q", got)
	}
}

func TestHTTPBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("接続に失敗: %v", err)
	}
	defer func() { _ = conn.Close() }()

	got := httpBanner(conn, u.Hostname(), time.Second)
	if !strings.Contains(got, "Server: test-server/1.0") {
		t.Errorf("httpBanner に Server ヘッダが含まれない: %q", got)
	}
	if !strings.Contains(got, "200") {
		t.Errorf("httpBanner にステータス行が含まれない: %q", got)
	}
}

func TestScan_WithBanner(t *testing.T) {
	port := bannerListener(t, "SSH-2.0-TestServer\r\n")
	cfg := Config{
		Host:       "127.0.0.1",
		PortStart:  port,
		PortEnd:    port,
		Threads:    1,
		Timeout:    time.Second,
		GrabBanner: true,
	}
	results, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Scan が失敗: %v", err)
	}
	if len(results) != 1 || results[0].Banner != "SSH-2.0-TestServer" {
		t.Errorf("バナーが取得できていない: %+v", results)
	}
}

func TestScan_NoBannerByDefault(t *testing.T) {
	// GrabBanner=false（既定）ではバナーを取得しない。
	port := bannerListener(t, "SSH-2.0-TestServer\r\n")
	cfg := Config{Host: "127.0.0.1", PortStart: port, PortEnd: port, Threads: 1, Timeout: time.Second}
	results, err := Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Scan が失敗: %v", err)
	}
	if len(results) != 1 || results[0].Banner != "" {
		t.Errorf("既定でバナーを取得してしまった: %+v", results)
	}
}
