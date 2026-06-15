package risk

import (
	"encoding/json"
	"testing"
)

func TestLookup_KnownPort(t *testing.T) {
	info, ok := Lookup(6379) // Redis
	if !ok {
		t.Fatal("6379(Redis) のリスク情報が見つからない")
	}
	if info.Severity != Critical {
		t.Errorf("6379 の深刻度=%v, want critical", info.Severity)
	}
	if len(info.Attacks) == 0 || len(info.Mitigations) == 0 {
		t.Errorf("6379 の攻撃/対策が空: %+v", info)
	}
}

func TestLookup_Unknown(t *testing.T) {
	if _, ok := Lookup(12345); ok {
		t.Error("未登録ポート 12345 で ok=true を返した")
	}
}

func TestSeverity_String(t *testing.T) {
	cases := map[Severity]string{
		Critical: "critical", High: "high", Medium: "medium", Low: "low",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String()=%q, want %q", s, got, want)
		}
	}
}

func TestSeverity_JSONRoundTrip(t *testing.T) {
	for _, s := range []Severity{Critical, High, Medium, Low} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("Marshal(%v) 失敗: %v", s, err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("Unmarshal(%s) 失敗: %v", b, err)
		}
		if got != s {
			t.Errorf("ラウンドトリップ不一致: %v -> %s -> %v", s, b, got)
		}
	}
}

// TestDatabase_Consistency は全エントリが最低限の情報を備え、
// 「広めにカバー」の方針どおり十分な件数があることを検証する。
func TestDatabase_Consistency(t *testing.T) {
	if len(database) < 50 {
		t.Errorf("収録ポート数=%d, want >= 50", len(database))
	}
	for port, info := range database {
		if info.Severity < Low || info.Severity > Critical {
			t.Errorf("port %d: 深刻度が範囲外: %d", port, info.Severity)
		}
		if info.Summary == "" {
			t.Errorf("port %d: Summary が空", port)
		}
		if len(info.Attacks) == 0 {
			t.Errorf("port %d: Attacks が空", port)
		}
		if len(info.Mitigations) == 0 {
			t.Errorf("port %d: Mitigations が空", port)
		}
	}
}
