// Package mdns は同一セグメント上のホストへ mDNS(Bonjour) 問い合わせを送り、
// ホスト名（xxx.local）とデバイスモデル（_device-info の model=）を収集する。
//
// mDNS はリンクローカルマルチキャスト（224.0.0.251:5353）を使うため、
// ルーターを越えない＝同一 L2 セグメント限定で機能する。スキャン中核の
// 「標準ライブラリのみ」方針に対し、本パッケージは DNS ワイヤーフォーマット
// 解析のため miekg/dns に依存する（TUI の bubbletea と並ぶ容認された例外）。
//
// 設計の要は「応答パケットの送信元 IP をキーにする」こと。1つの応答に含まれる
// 全レコードは同じホスト由来なので、SRV ターゲット追跡などのホスト間相関を
// せずに（IP → ホスト名／モデル）の対応を素直に組める。
package mdns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// mDNS のマルチキャストアドレスとポート（IPv4）。
var mdnsGroupIPv4 = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// Entry は1ホスト分の mDNS 収集結果を表す。
type Entry struct {
	Host  string // ホスト名（例: "Takashi-MacBook.local"）。末尾ドットは除去済み
	Model string // デバイスモデル（例: "Macmini9,1"）。取得できなければ空
}

// queryNames は応答を引き出すために問い合わせる名前。
// _services 列挙でホストを喋らせ、_device-info で model を含む TXT を引き出す。
var queryNames = []string{
	"_services._dns-sd._udp.local.",
	"_device-info._tcp.local.",
}

// Browse は timeout の間 mDNS 応答を収集し、IP 文字列 → Entry の対応を返す。
// 送信・受信に失敗しても可能な範囲の結果を返す（探索は best-effort）。
func Browse(ctx context.Context, timeout time.Duration) (map[string]Entry, error) {
	// 受信用: マルチキャストグループに参加して応答を待ち受ける。
	recv, err := net.ListenMulticastUDP("udp4", nil, mdnsGroupIPv4)
	if err != nil {
		return nil, err
	}
	defer func() { _ = recv.Close() }()

	// 送信用: エフェメラルポートからクエリをマルチキャストへ投げる。
	send, err := net.DialUDP("udp4", nil, mdnsGroupIPv4)
	if err != nil {
		return nil, err
	}
	defer func() { _ = send.Close() }()

	// クエリを送る。1パケットに複数 Question を載せて往復を減らす。
	if err := sendQueries(send); err != nil {
		return nil, err
	}

	deadline := timeNow().Add(timeout)
	_ = recv.SetReadDeadline(deadline)

	entries := make(map[string]Entry)
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			break
		}
		n, src, err := recv.ReadFromUDP(buf)
		if err != nil {
			break // タイムアウト等。収集を打ち切る
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue // 壊れたパケットは無視
		}
		ip := src.IP.String()
		merge(entries, ip, &msg)
	}
	return entries, nil
}

// sendQueries は queryNames の PTR 問い合わせをまとめて1パケットで送る。
func sendQueries(conn *net.UDPConn) error {
	m := new(dns.Msg)
	m.RecursionDesired = false
	for _, name := range queryNames {
		m.Question = append(m.Question, dns.Question{
			Name:   name,
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		})
	}
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = conn.Write(packed)
	return err
}

// merge は1応答メッセージ内のレコードを、送信元 IP の Entry へ畳み込む。
// A レコードからホスト名、_device-info の TXT(model=) からモデルを取り出す。
func merge(entries map[string]Entry, ip string, msg *dns.Msg) {
	e := entries[ip]
	for _, rr := range allRecords(msg) {
		switch v := rr.(type) {
		case *dns.A:
			if e.Host == "" {
				e.Host = trimDot(v.Hdr.Name)
			}
		case *dns.AAAA:
			if e.Host == "" {
				e.Host = trimDot(v.Hdr.Name)
			}
		case *dns.TXT:
			if m := modelFromTXT(v); m != "" {
				e.Model = m
			}
		}
	}
	if e.Host != "" || e.Model != "" {
		entries[ip] = e
	}
}

// allRecords は応答の全セクション（Answer/Ns/Extra）のレコードを連結する。
// A や device-info の TXT は Additional 節に載ることが多いため全節を見る。
func allRecords(msg *dns.Msg) []dns.RR {
	rrs := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	rrs = append(rrs, msg.Answer...)
	rrs = append(rrs, msg.Ns...)
	rrs = append(rrs, msg.Extra...)
	return rrs
}

// modelFromTXT は _device-info の TXT から "model=" の値を取り出す。
// 関係ない TXT（owner が _device-info でない）は無視する。
func modelFromTXT(txt *dns.TXT) string {
	if !strings.Contains(strings.ToLower(txt.Hdr.Name), "_device-info") {
		return ""
	}
	for _, kv := range txt.Txt {
		if v, ok := strings.CutPrefix(kv, "model="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

// timeNow は時刻取得を関数化してテストで差し替え可能にする。
var timeNow = time.Now
