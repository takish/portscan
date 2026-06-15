package osdetect

import (
	"encoding/json"
	"strings"
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

func TestDetectWithHints_ModelWins(t *testing.T) {
	// mDNS のモデルはポートプロファイルより優先し、high になる。
	results := []scanner.Result{open(22, "")} // 本来 Linux/Unix を弱く示唆
	g := DetectWithHints(results, Hints{Model: "Macmini9,1"})
	if g.OS != "macOS" || g.Confidence != ConfidenceHigh {
		t.Errorf("model ヒントが効いていない: %+v", g)
	}
}

func TestModelHint(t *testing.T) {
	cases := map[string]string{
		"MacBookPro18,3": "macOS",
		"Macmini9,1":     "macOS",
		"iMac21,1":       "macOS",
		"iPhone15,2":     "iOS",
		"iPad13,1":       "iPadOS",
		"AppleTV11,1":    "tvOS",
		"Watch6,1":       "watchOS",
	}
	for model, wantOS := range cases {
		g, ok := modelHint(model)
		if !ok || g.OS != wantOS {
			t.Errorf("modelHint(%q)=%q(ok=%v), want %q", model, g.OS, ok, wantOS)
		}
	}
	if _, ok := modelHint(""); ok {
		t.Error("空 model で ok=true になった")
	}
	if _, ok := modelHint("LinuxBox"); ok {
		t.Error("非 Apple model で ok=true になった")
	}
}

func TestModelHint_Device(t *testing.T) {
	// mDNS model からは OS だけでなく種別も確定できる（最も正確な手がかり）。
	cases := map[string]DeviceClass{
		"iPhone15,2":     DevicePhone,
		"iPad13,1":       DeviceTablet,
		"Watch6,1":       DeviceWatch,
		"AppleTV11,1":    DeviceTV,
		"MacBookPro18,3": DeviceComputer,
		"Macmini9,1":     DeviceComputer,
	}
	for model, want := range cases {
		g, ok := modelHint(model)
		if !ok || g.Device != want {
			t.Errorf("modelHint(%q).Device=%v(ok=%v), want %v", model, g.Device, ok, want)
		}
	}
}

func TestDeviceFromOS(t *testing.T) {
	// mDNS model が無いホストは OS 名から種別をフォールバック導出する。
	cases := map[string]DeviceClass{
		"iOS":                 DevicePhone,
		"iPadOS":              DeviceTablet,
		"watchOS":             DeviceWatch,
		"tvOS":                DeviceTV,
		"macOS":               DeviceComputer,
		"Windows":             DeviceComputer,
		"Linux (Ubuntu)":      DeviceComputer,
		"Linux/Unix":          DeviceComputer,
		"FreeBSD":             DeviceComputer,
		"ネットワーク機器 (MikroTik)": DeviceNetwork,
		"unknown":             DeviceUnknown,
		"":                    DeviceUnknown,
	}
	for os, want := range cases {
		if got := deviceFromOS(os); got != want {
			t.Errorf("deviceFromOS(%q)=%v, want %v", os, got, want)
		}
	}
}

func TestDetect_DeviceFromPortProfile(t *testing.T) {
	// model が無くても、OS 推定経由で種別が付く。Windows ポート群 → PC。
	g := Detect([]scanner.Result{open(135, ""), open(445, ""), open(3389, "")})
	if g.OS != "Windows" {
		t.Fatalf("OS=%q, want Windows", g.OS)
	}
	if g.Device != DeviceComputer {
		t.Errorf("Device=%v, want PC(Computer)", g.Device)
	}
}

func TestDetect_UnknownHasNoDevice(t *testing.T) {
	// OS 不明なら種別も判別不能のままにする。
	g := Detect([]scanner.Result{open(12345, "")})
	if g.Device.Known() {
		t.Errorf("unknown なのに種別が付いた: %v", g.Device)
	}
}

func TestDeviceClass_JSONRoundTrip(t *testing.T) {
	for _, d := range []DeviceClass{
		DevicePhone, DeviceTablet, DeviceComputer, DeviceWatch, DeviceTV, DeviceNetwork, DeviceUnknown,
	} {
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("Marshal 失敗: %v", err)
		}
		var got DeviceClass
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal 失敗: %v", err)
		}
		if got != d {
			t.Errorf("round-trip 不一致: %v -> %v", d, got)
		}
	}
}

func TestDeviceClass_OmitsUnknownInGuessJSON(t *testing.T) {
	// DeviceUnknown は omitempty で JSON から省略される（ノイズを出さない）。
	data, err := json.Marshal(Guess{OS: "Linux/Unix", Confidence: ConfidenceLow})
	if err != nil {
		t.Fatalf("Marshal 失敗: %v", err)
	}
	if strings.Contains(string(data), "device") {
		t.Errorf("Unknown 種別が JSON に出た: %s", data)
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
