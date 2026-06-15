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
