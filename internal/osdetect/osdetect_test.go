package osdetect

import (
	"encoding/json"
	"testing"

	"github.com/takish/portscan/internal/scanner"
)

func open(port int, banner string) scanner.Result {
	return scanner.Result{Port: port, Status: scanner.StatusOpen, Banner: banner}
}

func TestDetect_BannerWins(t *testing.T) {
	// バナーに OS 名があればポートプロファイルより優先し、high になる。
	results := []scanner.Result{
		open(3389, ""), // RDP（本来 Windows を示唆）
		open(80, "Apache/2.4.52 (Ubuntu)"),
	}
	g := Detect(results)
	if g.OS != "Linux (Ubuntu)" {
		t.Errorf("OS=%q, want Linux (Ubuntu)", g.OS)
	}
	if g.Confidence != ConfidenceHigh {
		t.Errorf("Confidence=%s, want high", g.Confidence)
	}
}

func TestDetect_WindowsPortProfile(t *testing.T) {
	// RDP+SMB+NetBIOS の組み合わせで Windows を medium 確度で推定。
	results := []scanner.Result{open(135, ""), open(139, ""), open(445, ""), open(3389, "")}
	g := Detect(results)
	if g.OS != "Windows" {
		t.Errorf("OS=%q, want Windows", g.OS)
	}
	if g.Confidence != ConfidenceMedium {
		t.Errorf("Confidence=%s, want medium", g.Confidence)
	}
	if len(g.Reasons) == 0 {
		t.Error("根拠が空")
	}
}

func TestDetect_SSHOnlyIsLowUnix(t *testing.T) {
	// SSH だけなら Unix 系を low 確度で推定する。
	g := Detect([]scanner.Result{open(22, "")})
	if g.OS != "Linux/Unix" {
		t.Errorf("OS=%q, want Linux/Unix", g.OS)
	}
	if g.Confidence != ConfidenceLow {
		t.Errorf("Confidence=%s, want low", g.Confidence)
	}
}

func TestDetect_macOS(t *testing.T) {
	// AFP は macOS を強く示唆する。
	g := Detect([]scanner.Result{open(548, ""), open(22, "")})
	if g.OS != "macOS" {
		t.Errorf("OS=%q, want macOS", g.OS)
	}
}

func TestDetect_Unknown(t *testing.T) {
	// 手がかりの無いポートだけなら unknown。
	g := Detect([]scanner.Result{open(12345, "")})
	if g.Known() {
		t.Errorf("手がかり無しで Known=true: %+v", g)
	}
	if g.OS != OSUnknown || g.Confidence != ConfidenceLow {
		t.Errorf("unknown 推定が不正: %+v", g)
	}
}

func TestDetect_IgnoresNonOpen(t *testing.T) {
	// filtered ポートは判定材料にしない。
	results := []scanner.Result{
		{Port: 3389, Status: scanner.StatusFiltered},
		open(22, ""),
	}
	g := Detect(results)
	if g.OS != "Linux/Unix" {
		t.Errorf("filtered を材料にしてしまった: %+v", g)
	}
}

func TestConfidence_JSONRoundTrip(t *testing.T) {
	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("Marshal 失敗: %v", err)
		}
		var got Confidence
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal 失敗: %v", err)
		}
		if got != c {
			t.Errorf("round-trip 不一致: %s -> %s", c, got)
		}
	}
}
