package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// maxBannerLen は取得・保持するバナー文字列の最大長（文字数）。
// 過大・悪意ある応答でメモリや表示を圧迫しないよう切り詰める。
const maxBannerLen = 256

// httpPorts は接続直後にバナーを送らず、リクエストを送って初めて
// 応答する HTTP（平文）系ポート。これらは即リクエストを送る。
var httpPorts = map[int]bool{
	80: true, 3000: true, 5000: true, 5173: true,
	8000: true, 8080: true, 8888: true, 9000: true, 9090: true,
}

// tlsPorts は TLS ハンドシェイクを要する代表的ポート。
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 993: true, 995: true, 2376: true, 8443: true,
}

// grabBanner は開放ポートへ接続し、サービスが返すバナー文字列を取得する。
// 取得できない場合は空文字を返す（バナー取得の失敗はスキャン結果に影響させない）。
//
// プロトコルごとに挙動が異なるため経路を分ける:
//   - TLS 系       : ハンドシェイクし TLS バージョン・証明書 CN（＋HTTP なら Server）を取得
//   - HTTP（平文）系: 簡易 GET を送って応答行・Server ヘッダを取得
//   - その他       : 接続直後に送られるバナー（SSH/FTP/SMTP 等）を読む
func grabBanner(ctx context.Context, host string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	switch {
	case tlsPorts[port]:
		return tlsBanner(ctx, conn, host, port, timeout)
	case httpPorts[port]:
		return httpBanner(conn, host, timeout)
	default:
		return readBanner(conn, timeout)
	}
}

// readBanner は接続直後にサーバが自発的に送るバナーを読み取る。
func readBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBannerLen)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return clip(string(buf[:n]))
}

// httpBanner は簡易 HTTP リクエストを送り、ステータス行と Server ヘッダを取得する。
func httpBanner(conn net.Conn, host string, timeout time.Duration) string {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscan\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	status, _ := r.ReadString('\n')
	status = strings.TrimSpace(status)

	// ヘッダを走査して Server を探す（空行でヘッダ終端）。
	server := ""
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[len("server:"):])
			break
		}
		if err != nil {
			break
		}
	}

	switch {
	case status != "" && server != "":
		return clip(status + " | Server: " + server)
	case status != "":
		return clip(status)
	default:
		return ""
	}
}

// tlsBanner は TLS ハンドシェイクを行い、バージョンと証明書情報を取得する。
// HTTPS 系ポートでは続けて HTTP の Server ヘッダも取得する。
func tlsBanner(ctx context.Context, conn net.Conn, host string, port int, timeout time.Duration) string {
	// 証明書検証は目的外（到達確認＋情報取得）なので無効化する。
	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	if err := tconn.HandshakeContext(ctx); err != nil {
		return ""
	}

	st := tconn.ConnectionState()
	parts := []string{"TLS " + tlsVersionString(st.Version)}
	if len(st.PeerCertificates) > 0 {
		if cn := st.PeerCertificates[0].Subject.CommonName; cn != "" {
			parts = append(parts, "CN="+cn)
		}
	}
	if port == 443 || port == 8443 {
		if hb := httpBanner(tconn, host, timeout); hb != "" {
			parts = append(parts, hb)
		}
	}
	return clip(strings.Join(parts, " | "))
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// clip はバナーを1行に丸め、制御文字を除去し、長さを制限する。
func clip(s string) string {
	// 最初の行のみを採用（複数行バナーの後続は捨てる）。
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	// 制御文字（および DEL）を除去する。
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxBannerLen {
		s = s[:maxBannerLen]
	}
	return s
}
