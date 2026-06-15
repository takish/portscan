package mdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestModelFromTXT(t *testing.T) {
	// _device-info の TXT から model= を取り出す。
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "Foo._device-info._tcp.local."},
		Txt: []string{"model=Macmini9,1", "osxvers=22"},
	}
	if got := modelFromTXT(txt); got != "Macmini9,1" {
		t.Errorf("model=%q, want Macmini9,1", got)
	}

	// _device-info 以外の TXT は無視する。
	other := &dns.TXT{
		Hdr: dns.RR_Header{Name: "Foo._http._tcp.local."},
		Txt: []string{"model=ShouldBeIgnored"},
	}
	if got := modelFromTXT(other); got != "" {
		t.Errorf("無関係な TXT から model を拾った: %q", got)
	}
}

func TestMerge(t *testing.T) {
	// A レコードからホスト名、device-info TXT からモデルを畳み込む。
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "Mac.local."}, A: net.IPv4(192, 168, 1, 5)},
		},
		Extra: []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "Mac._device-info._tcp.local."},
				Txt: []string{"model=MacBookPro18,3"},
			},
		},
	}
	entries := map[string]Entry{}
	merge(entries, "192.168.1.5", msg)

	e, ok := entries["192.168.1.5"]
	if !ok {
		t.Fatal("送信元 IP の Entry が作られていない")
	}
	if e.Host != "Mac.local" {
		t.Errorf("Host=%q, want Mac.local（末尾ドット除去）", e.Host)
	}
	if e.Model != "MacBookPro18,3" {
		t.Errorf("Model=%q, want MacBookPro18,3", e.Model)
	}
}

func TestMerge_NoUsefulRecords(t *testing.T) {
	// 有用なレコードが無ければ Entry を作らない。
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.PTR{Hdr: dns.RR_Header{Name: "_services._dns-sd._udp.local."}, Ptr: "_smb._tcp.local."},
		},
	}
	entries := map[string]Entry{}
	merge(entries, "192.168.1.9", msg)
	if _, ok := entries["192.168.1.9"]; ok {
		t.Error("有用な情報が無いのに Entry を作ってしまった")
	}
}

func TestLookup(t *testing.T) {
	entries := map[string]Entry{
		"192.168.1.5": {Host: "Mac.local", Model: "Macmini9,1"},
	}
	// IP キーで直接ヒットする。
	if e, ok := Lookup(entries, "192.168.1.5"); !ok || e.Model != "Macmini9,1" {
		t.Errorf("IP 直引きに失敗: %+v ok=%v", e, ok)
	}
	// 未知のホストはヒットしない（名前解決しても一致しない）。
	if _, ok := Lookup(entries, "203.0.113.1"); ok {
		t.Error("未知ホストでヒットした")
	}
	// 空マップは常に false。
	if _, ok := Lookup(nil, "192.168.1.5"); ok {
		t.Error("空マップでヒットした")
	}
}

func TestTrimDot(t *testing.T) {
	if got := trimDot("host.local."); got != "host.local" {
		t.Errorf("trimDot=%q, want host.local", got)
	}
	if got := trimDot("host.local"); got != "host.local" {
		t.Errorf("ドット無しを変えてしまった: %q", got)
	}
}

func TestSendQueries_Packs(t *testing.T) {
	// クエリメッセージが正しく組み立てられ Pack できることを確認する。
	m := new(dns.Msg)
	for _, name := range queryNames {
		m.Question = append(m.Question, dns.Question{Name: name, Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	}
	if _, err := m.Pack(); err != nil {
		t.Fatalf("クエリの Pack に失敗: %v", err)
	}
	if len(m.Question) != len(queryNames) {
		t.Errorf("Question 数=%d, want %d", len(m.Question), len(queryNames))
	}
}
