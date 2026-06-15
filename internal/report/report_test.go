package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/takish/portscan/internal/scanner"
)

var sample = []scanner.Result{
	{Port: 22, Status: scanner.StatusOpen, Service: "SSH"},
	{Port: 80, Status: scanner.StatusOpen, Service: "HTTP"},
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "json", "csv"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q) で予期せぬエラー: %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("不正な形式 'xml' でエラーが返るべき")
	}
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample, FormatText); err != nil {
		t.Fatalf("Render が失敗: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "22") || !strings.Contains(out, "SSH") || !strings.Contains(out, "open") {
		t.Errorf("text 出力に期待値が含まれない:\n%s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample, FormatJSON); err != nil {
		t.Fatalf("Render が失敗: %v", err)
	}
	var got []scanner.Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON として解析できない: %v\n%s", err, buf.String())
	}
	if len(got) != 2 || got[0].Port != 22 {
		t.Errorf("JSON 解析結果が不正: %+v", got)
	}
	// Status は文字列として出力されること。
	if !strings.Contains(buf.String(), `"status": "open"`) {
		t.Errorf("status が文字列で出力されていない:\n%s", buf.String())
	}
}

func TestRenderJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, nil, FormatJSON); err != nil {
		t.Fatalf("Render が失敗: %v", err)
	}
	// nil でも "null" ではなく空配列 "[]" になること。
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Errorf("空結果の JSON が %q、want []", got)
	}
}

var sampleHosts = []HostScan{
	{Host: "192.168.1.1", Results: []scanner.Result{{Port: 80, Status: scanner.StatusOpen, Service: "HTTP"}}},
	{Host: "192.168.1.2", Results: []scanner.Result{{Port: 22, Status: scanner.StatusOpen, Service: "SSH"}}},
}

func TestRenderHostScans_Text(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHostScans(&buf, sampleHosts, FormatText); err != nil {
		t.Fatalf("RenderHostScans が失敗: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "=== 192.168.1.1 ===") || !strings.Contains(out, "HTTP") {
		t.Errorf("ホスト別 text 出力が不正:\n%s", out)
	}
}

func TestRenderHostScans_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHostScans(&buf, sampleHosts, FormatJSON); err != nil {
		t.Fatalf("RenderHostScans が失敗: %v", err)
	}
	var got []HostScan
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON として解析できない: %v\n%s", err, buf.String())
	}
	if len(got) != 2 || got[0].Host != "192.168.1.1" || got[0].Results[0].Port != 80 {
		t.Errorf("JSON 解析結果が不正: %+v", got)
	}
}

func TestRenderHostScans_CSV(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHostScans(&buf, sampleHosts, FormatCSV); err != nil {
		t.Fatalf("RenderHostScans が失敗: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "host,port,status,service") {
		t.Errorf("CSV ヘッダが不正:\n%s", out)
	}
	if !strings.Contains(out, "192.168.1.1,80,open,HTTP") {
		t.Errorf("CSV 行が不正:\n%s", out)
	}
}

func TestRenderCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample, FormatCSV); err != nil {
		t.Fatalf("Render が失敗: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "port,status,service") {
		t.Errorf("CSV ヘッダが不正:\n%s", out)
	}
	if !strings.Contains(out, "22,open,SSH") {
		t.Errorf("CSV 行が不正:\n%s", out)
	}
}
