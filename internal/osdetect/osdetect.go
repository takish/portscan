// Package osdetect は開放ポートのプロファイルと（取得済みなら）バナー文字列から
// 対象ホストの OS を軽量に推定する。root 権限や生パケット送出は不要で、
// scanner の結果だけを材料にするヒューリスティック判定である。
//
// 確実な OS フィンガープリンティング（TCP/IP スタックの挙動解析など）は行わない。
// あくまで「開いているポートの顔ぶれ」と「バナーに現れる文字列」から推測するため、
// 結果には必ず確度（high/medium/low）を添えて限界を正直に伝える。
package osdetect

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/takish/portscan/internal/scanner"
)

// Confidence は OS 推定の確からしさを表す。値が大きいほど確度が高い。
type Confidence int

const (
	ConfidenceLow    Confidence = iota // 単一・弱い手がかりのみ
	ConfidenceMedium                   // 特徴的なポートの組み合わせ
	ConfidenceHigh                     // バナーに OS 名が明示されている等
)

// String は確度の表示用文字列を返す。
func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

// MarshalJSON は Confidence を文字列として JSON 出力する。
func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON は文字列表現の Confidence を読み戻す。
func (c *Confidence) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "high":
		*c = ConfidenceHigh
	case "medium":
		*c = ConfidenceMedium
	case "low":
		*c = ConfidenceLow
	default:
		return fmt.Errorf("不明な Confidence: %q", s)
	}
	return nil
}

// OSUnknown は推定できなかった場合の OS 名。
const OSUnknown = "unknown"

// Guess は1ホストに対する OS 推定の結果を表す。
type Guess struct {
	OS         string     `json:"os"`                // 推定 OS（不明なら "unknown"）
	Confidence Confidence `json:"confidence"`        // 推定の確度
	Reasons    []string   `json:"reasons,omitempty"` // 判定根拠（人間向け）
}

// Known は何らかの手がかりから OS を推定できたかを返す。
func (g Guess) Known() bool { return g.OS != "" && g.OS != OSUnknown }

// bannerHint はバナー中に現れる部分文字列と、それが示す OS の対応。
// 小文字で比較する。明示的な OS 名はもっとも強い手がかりなので high とする。
var bannerHints = []struct {
	sub string
	os  string
}{
	{"ubuntu", "Linux (Ubuntu)"},
	{"debian", "Linux (Debian)"},
	{"centos", "Linux (CentOS)"},
	{"red hat", "Linux (RHEL)"},
	{"fedora", "Linux (Fedora)"},
	{"alpine", "Linux (Alpine)"},
	{"raspbian", "Linux (Raspbian)"},
	{"microsoft-iis", "Windows"},
	{"win32", "Windows"},
	{"win64", "Windows"},
	{"windows", "Windows"},
	{"darwin", "macOS"},
	{"mac os", "macOS"},
	{"macos", "macOS"},
	{"freebsd", "FreeBSD"},
	{"openbsd", "OpenBSD"},
	{"netbsd", "NetBSD"},
	{"mikrotik", "ネットワーク機器 (MikroTik)"},
	{"routeros", "ネットワーク機器 (RouterOS)"},
	{"openwrt", "ネットワーク機器 (OpenWrt)"},
	{"dd-wrt", "ネットワーク機器 (DD-WRT)"},
	{"cisco", "ネットワーク機器 (Cisco)"},
}

// portSignal は1つの開放ポートが示す OS の手がかり（重み付き）。
type portSignal struct {
	os     string
	weight int
	reason string
}

// portSignals はポート番号 → OS 手がかりの対応表。
// 値が大きいほどその OS を強く示唆する。
var portSignals = map[int]portSignal{
	3389: {"Windows", 3, "3389/RDP 開放"},
	445:  {"Windows", 2, "445/SMB 開放"},
	1433: {"Windows", 2, "1433/MSSQL 開放"},
	135:  {"Windows", 1, "135/MSRPC 開放"},
	139:  {"Windows", 1, "139/NetBIOS 開放"},
	5985: {"Windows", 2, "5985/WinRM 開放"},
	5986: {"Windows", 2, "5986/WinRM(S) 開放"},
	548:  {"macOS", 3, "548/AFP 開放"},
	5009: {"macOS", 2, "5009/AirPort 開放"},
	2049: {"Linux/Unix", 1, "2049/NFS 開放"},
	111:  {"Linux/Unix", 1, "111/rpcbind 開放"},
}

// Detect は開放ポート（と取得済みバナー）から OS を推定する。
// まずバナーの明示的な OS 名を探し、無ければ開放ポートの顔ぶれをスコアリングする。
func Detect(results []scanner.Result) Guess {
	open := make(map[int]bool)
	var banners []string
	for _, r := range results {
		if r.Status != scanner.StatusOpen {
			continue
		}
		open[r.Port] = true
		if r.Banner != "" {
			banners = append(banners, strings.ToLower(r.Banner))
		}
	}

	// 1. バナーの明示的な OS 名（最も確度が高い）。
	for _, b := range banners {
		for _, h := range bannerHints {
			if strings.Contains(b, h.sub) {
				return Guess{
					OS:         h.os,
					Confidence: ConfidenceHigh,
					Reasons:    []string{fmt.Sprintf("バナーに %q を検出", h.sub)},
				}
			}
		}
	}

	// 2. 開放ポートのプロファイルをスコアリングする。
	scores := make(map[string]int)
	reasons := make(map[string][]string)
	for port := range open {
		if sig, ok := portSignals[port]; ok {
			scores[sig.os] += sig.weight
			reasons[sig.os] = append(reasons[sig.os], sig.reason)
		}
	}
	// SSH が開いていて Windows 特有ポートが無ければ Unix 系を弱く示唆する。
	if open[22] && !open[445] && !open[3389] && !open[135] {
		scores["Linux/Unix"]++
		reasons["Linux/Unix"] = append(reasons["Linux/Unix"], "22/SSH 開放・SMB/RDP なし")
	}

	if len(scores) == 0 {
		return Guess{OS: OSUnknown, Confidence: ConfidenceLow}
	}

	// 最高スコアの OS を選ぶ。同点は OS 名の辞書順で安定させる。
	var bestOS string
	bestScore := -1
	for os := range scores {
		if scores[os] > bestScore || (scores[os] == bestScore && os < bestOS) {
			bestOS, bestScore = os, scores[os]
		}
	}

	conf := ConfidenceLow
	if bestScore >= 3 {
		conf = ConfidenceMedium
	}

	rs := reasons[bestOS]
	sort.Strings(rs)
	return Guess{OS: bestOS, Confidence: conf, Reasons: rs}
}
