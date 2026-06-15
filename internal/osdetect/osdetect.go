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

// 表示ラベル。OS 推定行の見出しを report / tui で共通化し、文言のズレを防ぐ。
// 確度の値表現（Confidence.String）と同様、表示語彙は osdetect に集約する。
const (
	LabelOS         = "推定OS"
	LabelConfidence = "確度"
	LabelDevice     = "種別"
)

// OSUnknown は推定できなかった場合の OS 名。
const OSUnknown = "unknown"

// DeviceClass はホストのデバイス種別。mDNS model（最も正確）または推定 OS から導出する。
type DeviceClass int

const (
	DeviceUnknown  DeviceClass = iota // 判別不能
	DevicePhone                       // スマートフォン
	DeviceTablet                      // タブレット
	DeviceComputer                    // PC（デスクトップ/ノート/サーバを含む）
	DeviceWatch                       // スマートウォッチ
	DeviceTV                          // テレビ/セットトップボックス
	DeviceNetwork                     // ルーター等のネットワーク機器
)

// String は種別の表示用文字列（日本語）を返す。表示語彙は osdetect に集約する。
func (d DeviceClass) String() string {
	switch d {
	case DevicePhone:
		return "スマートフォン"
	case DeviceTablet:
		return "タブレット"
	case DeviceComputer:
		return "PC"
	case DeviceWatch:
		return "スマートウォッチ"
	case DeviceTV:
		return "TV"
	case DeviceNetwork:
		return "ネットワーク機器"
	default:
		return "不明"
	}
}

// Known は種別を判別できたかを返す。
func (d DeviceClass) Known() bool { return d != DeviceUnknown }

// deviceKeys は DeviceClass と JSON 表現（安定した英語キー）の対応。
var deviceKeys = map[DeviceClass]string{
	DevicePhone:    "phone",
	DeviceTablet:   "tablet",
	DeviceComputer: "computer",
	DeviceWatch:    "watch",
	DeviceTV:       "tv",
	DeviceNetwork:  "network",
}

// MarshalJSON は DeviceClass を安定した英語キーで出力する（表示用 String とは別系統）。
func (d DeviceClass) MarshalJSON() ([]byte, error) {
	s, ok := deviceKeys[d]
	if !ok {
		s = "unknown"
	}
	return json.Marshal(s)
}

// UnmarshalJSON は英語キーから DeviceClass を復元する。
func (d *DeviceClass) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "unknown" {
		*d = DeviceUnknown
		return nil
	}
	for k, v := range deviceKeys {
		if v == s {
			*d = k
			return nil
		}
	}
	return fmt.Errorf("不明な DeviceClass: %q", s)
}

// Guess は1ホストに対する OS 推定の結果を表す。
type Guess struct {
	OS         string      `json:"os"`                // 推定 OS（不明なら "unknown"）
	Device     DeviceClass `json:"device,omitempty"`  // デバイス種別（判別不能なら省略）
	Confidence Confidence  `json:"confidence"`        // 推定の確度
	Reasons    []string    `json:"reasons,omitempty"` // 判定根拠（人間向け）
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

// Hints は開放ポート以外の補助的な判定材料。mDNS 等から得た情報を渡す。
type Hints struct {
	Model string // mDNS _device-info の model（例: "Macmini9,1"）
	TTL   int    // ICMP echo 応答の受信 TTL（0 なら未取得）
}

// ttlFamily は ICMP 応答の受信 TTL から送信元ホストの OS 系統を推定する。
// OS の初期 TTL は 64(Unix系) / 128(Windows) / 255(ネットワーク機器) が代表的で、
// 経路の各ホップで 1 ずつ減るため「受信値以上で最も近い初期値」を採用する。
// ホップ数が過大（同一/近接セグメントの想定を超える）な場合は判別不能とする。
func ttlFamily(recv int) (os string, ok bool) {
	if recv <= 0 {
		return "", false
	}
	cands := []struct {
		init int
		os   string
	}{
		{64, "Linux/Unix"},
		{128, "Windows"},
		{255, "ネットワーク機器"},
	}
	best := ""
	bestHops := 1 << 30
	for _, c := range cands {
		if recv <= c.init && c.init-recv < bestHops {
			bestHops, best = c.init-recv, c.os
		}
	}
	// ホップ数が大きすぎる推定は信頼できないので捨てる（誤分類の防止）。
	if best == "" || bestHops > 32 {
		return "", false
	}
	return best, true
}

// ttlMatchesOS は推定済み OS 名が TTL 由来の系統 fam と整合するかを返す。
func ttlMatchesOS(osName, fam string) bool {
	switch fam {
	case "Windows":
		return osName == "Windows"
	case "ネットワーク機器":
		return strings.HasPrefix(osName, "ネットワーク機器")
	case "Linux/Unix":
		// Unix 系全般（Linux 各種・macOS・*BSD・Apple モバイル OS）。
		switch osName {
		case "Linux/Unix", "macOS", "FreeBSD", "OpenBSD", "NetBSD",
			"iOS", "iPadOS", "watchOS", "tvOS":
			return true
		}
		return strings.HasPrefix(osName, "Linux")
	}
	return false
}

// applyTTL は TTL 由来の系統情報を base の推定へ反映する。
//   - スキャンから何も分からなければ TTL 系統を medium 確度で採用する
//   - 既存推定と一致すれば確度を一段引き上げ、根拠を補強する
//   - 矛盾する場合は OS は変えず、所見だけ根拠に残して判断材料にする
func applyTTL(base Guess, recvTTL int) Guess {
	fam, ok := ttlFamily(recvTTL)
	if !ok {
		return base
	}
	reason := fmt.Sprintf("ICMP TTL=%d → %s系", recvTTL, fam)
	if !base.Known() {
		return Guess{
			OS:         fam,
			Device:     deviceFromOS(fam),
			Confidence: ConfidenceMedium,
			Reasons:    []string{reason},
		}
	}
	if ttlMatchesOS(base.OS, fam) {
		if base.Confidence < ConfidenceHigh {
			base.Confidence++
		}
		base.Reasons = append(base.Reasons, reason)
	} else {
		base.Reasons = append(base.Reasons, reason+"（ポート推定と不一致）")
	}
	return base
}

// modelHint はデバイスモデル文字列から OS を推定する。
// model はメーカー定義の機種コードで、Apple 製品なら接頭辞でほぼ確定できる。
func modelHint(model string) (Guess, bool) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return Guess{}, false
	}
	reason := []string{fmt.Sprintf("mDNS model=%q", model)}
	switch {
	case strings.HasPrefix(m, "iphone"):
		return Guess{OS: "iOS", Device: DevicePhone, Confidence: ConfidenceHigh, Reasons: reason}, true
	case strings.HasPrefix(m, "ipad"):
		return Guess{OS: "iPadOS", Device: DeviceTablet, Confidence: ConfidenceHigh, Reasons: reason}, true
	case strings.HasPrefix(m, "watch"):
		return Guess{OS: "watchOS", Device: DeviceWatch, Confidence: ConfidenceHigh, Reasons: reason}, true
	case strings.HasPrefix(m, "appletv"):
		return Guess{OS: "tvOS", Device: DeviceTV, Confidence: ConfidenceHigh, Reasons: reason}, true
	case strings.HasPrefix(m, "mac") || strings.HasPrefix(m, "imac") || strings.HasPrefix(m, "macbook"):
		return Guess{OS: "macOS", Device: DeviceComputer, Confidence: ConfidenceHigh, Reasons: reason}, true
	}
	return Guess{}, false
}

// deviceFromOS は推定 OS 名から最も妥当なデバイス種別を導出する。
// mDNS model が無いホスト向けのフォールバックで、種別の確度は OS 推定の確度に従う。
func deviceFromOS(os string) DeviceClass {
	switch {
	case os == "iOS":
		return DevicePhone
	case os == "iPadOS":
		return DeviceTablet
	case os == "watchOS":
		return DeviceWatch
	case os == "tvOS":
		return DeviceTV
	case os == "macOS", os == "Windows", os == "FreeBSD", os == "OpenBSD", os == "NetBSD":
		return DeviceComputer
	case strings.HasPrefix(os, "Linux"):
		return DeviceComputer
	case strings.HasPrefix(os, "ネットワーク機器"):
		return DeviceNetwork
	default:
		return DeviceUnknown
	}
}

// Detect は開放ポート（と取得済みバナー）から OS を推定する。
// mDNS 等の補助情報を加味したい場合は DetectWithHints を使う。
func Detect(results []scanner.Result) Guess {
	return DetectWithHints(results, Hints{})
}

// DetectWithHints は補助情報 h も加味して OS を推定する。
// mDNS のモデル情報は最も確実な手がかりなので、あれば最優先で採用する。
// それ以外はスキャン由来の推定に TTL 系統ヒントを重ねて補強する。
func DetectWithHints(results []scanner.Result, h Hints) Guess {
	if g, ok := modelHint(h.Model); ok {
		return g
	}
	return applyTTL(detectFromScan(results), h.TTL)
}

// detectFromScan は開放ポートとバナーのみから OS を推定する内部実装。
func detectFromScan(results []scanner.Result) Guess {
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
					Device:     deviceFromOS(h.os),
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
	return Guess{OS: bestOS, Device: deviceFromOS(bestOS), Confidence: conf, Reasons: rs}
}
