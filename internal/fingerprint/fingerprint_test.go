package fingerprint

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestResolveIPv4(t *testing.T) {
	// IPv4 リテラルはそのまま解決できる。
	if ip, ok := resolveIPv4("127.0.0.1"); !ok || ip.To4() == nil {
		t.Errorf("127.0.0.1 を IPv4 解決できない: ip=%v ok=%v", ip, ok)
	}
	// IPv6 リテラルは対象外（ok=false）。
	if _, ok := resolveIPv4("::1"); ok {
		t.Error("IPv6 を対象にしてしまった")
	}
	// 解決不能な名前は ok=false。
	if _, ok := resolveIPv4("no-such-host.invalid"); ok {
		t.Error("解決不能な名前で ok=true になった")
	}
	// localhost は IPv4 を持つ。
	if _, ok := resolveIPv4("localhost"); !ok {
		t.Error("localhost を IPv4 解決できない")
	}
}

func TestProbeTTL_Loopback(t *testing.T) {
	// ループバックは確実に応答するはず。ただし非特権 ICMP が許可されない
	// CI 環境もあるため、取得できない場合はスキップ（失敗にはしない）。
	ttl, ok := ProbeTTL(context.Background(), "127.0.0.1", 2*time.Second)
	if !ok {
		t.Skip("非特権 ICMP が使えない環境のためスキップ")
	}
	if ttl <= 0 || ttl > 255 {
		t.Errorf("TTL=%d は範囲外", ttl)
	}
}

func TestProbeTTL_UnresolvableReturnsFalse(t *testing.T) {
	// 解決できないホストは ICMP を送る前に false を返す。
	if _, ok := ProbeTTL(context.Background(), "no-such-host.invalid", 200*time.Millisecond); ok {
		t.Error("解決不能ホストで ok=true になった")
	}
}

func TestProbeTTL_IPv6TargetReturnsFalse(t *testing.T) {
	// IPv6 のみの宛先は対象外。
	if _, ok := ProbeTTL(context.Background(), net.IPv6loopback.String(), 200*time.Millisecond); ok {
		t.Error("IPv6 宛先で ok=true になった")
	}
}
