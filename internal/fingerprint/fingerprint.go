// Package fingerprint は ICMP echo（ping）応答パケットの TTL を観測して、
// 対象ホストの OS 系統を推定する材料を集める。
//
// OS ごとに IP パケットの初期 TTL が異なる（Unix 系=64 / Windows=128 /
// ネットワーク機器=255）ことを利用する。raw socket や pcap は使わず、
// 非特権 ICMP datagram socket（golang.org/x/net/icmp）だけで動くため、
// root 権限も cgo（libpcap）も不要で単一バイナリ配布を保てる。
//
// 受信 TTL の「初期値推定」や OS 系統への対応付けは観測値の解釈であり、
// OS 推定の責務をもつ osdetect 側に置く。本パッケージは ICMP I/O に徹し、
// 観測した受信 TTL をそのまま返す。
package fingerprint

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ProbeTTL は host へ ICMP echo を1発送り、応答パケットの受信 TTL を返す。
// 非特権 ICMP datagram socket を用いるため root 権限は不要。
//
// 応答が無い（ICMP 不通・フィルタ・タイムアウト）場合や IPv4 で解決できない
// 場合は ok=false を返す。OS フィンガープリントは best-effort な補助情報なので、
// 失敗は呼び出し側で「TTL ヒント無し」として扱えばよい。
func ProbeTTL(ctx context.Context, host string, timeout time.Duration) (ttl int, ok bool) {
	ip, ok := resolveIPv4(host)
	if !ok {
		return 0, false
	}

	// "udp4" 指定は非特権 ICMP datagram socket を開く（root 不要）。
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, false
	}
	defer func() { _ = c.Close() }()

	// 受信パケットの TTL を制御メッセージで受け取れるようにする。
	p := c.IPv4PacketConn()
	if err := p.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		return 0, false
	}

	id := os.Getpid() & 0xffff
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("portscan-ttl")},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, false
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: ip}); err != nil {
		return 0, false
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetReadDeadline(deadline)

	rb := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return 0, false
		}
		n, cm, _, err := p.ReadFrom(rb)
		if err != nil {
			return 0, false // タイムアウト等。応答無しとして扱う
		}
		m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
		if err != nil {
			continue
		}
		// 非特権 ICMP socket ではカーネルが echo の ID を書き換えるため、
		// ID 一致ではなく「echo reply 型か」で判定する。socket は宛先ごとに
		// 独立して開くので、他ホストの応答が紛れ込む余地は実質ない。
		if m.Type == ipv4.ICMPTypeEchoReply {
			if cm == nil {
				return 0, false
			}
			return cm.TTL, true
		}
	}
}

// resolveIPv4 は host（IP 文字列または名前）を IPv4 アドレスへ解決する。
// IPv6 のみのホストは TTL プローブの対象外とし ok=false を返す。
func resolveIPv4(host string) (net.IP, bool) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, true
		}
		return nil, false
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, false
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, true
		}
	}
	return nil, false
}
