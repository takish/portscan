// Package report はスキャン結果を各種フォーマットで出力する。
// 開放ポートに既知のセキュリティリスクがある場合は、描画時に
// internal/risk を引いて深刻度・代表攻撃・対策を併記する（常に表示）。
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/takish/portscan/internal/osdetect"
	"github.com/takish/portscan/internal/risk"
	"github.com/takish/portscan/internal/scanner"
)

// Format は出力フォーマットの種類を表す。
type Format string

const (
	FormatText Format = "text" // 人間向けのプレーンテキスト
	FormatJSON Format = "json" // JSON 配列
	FormatCSV  Format = "csv"  // CSV（ヘッダ付き）
)

// ParseFormat は文字列を Format に変換する。未知の値はエラーを返す。
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatCSV:
		return Format(s), nil
	default:
		return "", fmt.Errorf("不明な出力形式: %q (text/json/csv のいずれか)", s)
	}
}

// Meta はポート結果以外の補助情報（mDNS 由来のホスト名・モデル等）。
// OS 推定の手がかりや出力のホスト名表示に使う。空でも構わない。
type Meta struct {
	Hostname string // mDNS で得たホスト名（例: "Foo.local"）
	Model    string // mDNS で得たデバイスモデル（例: "Macmini9,1"）
}

// HostScan は1台のホストに対するスキャン結果を表す。
type HostScan struct {
	Host    string           `json:"host"`
	Results []scanner.Result `json:"ports"`
	Meta    Meta             `json:"-"` // mDNS 由来の補助情報（出力は各レンダラが整形）
}

// resultWithRisk は1ポートの結果にリスク情報を添えた出力用 DTO。
// scanner.Result を埋め込み、その JSON フィールド(port/status/service)を
// 引き継ぎつつ risk を付加する。
type resultWithRisk struct {
	scanner.Result
	Risk *risk.Info `json:"risk,omitempty"`
}

// scanReport は単一ホストの JSON 出力用 DTO。OS 推定はホスト単位の情報なので、
// ポート配列を直接出力するのではなく os と ports を持つオブジェクトに包む。
type scanReport struct {
	Hostname string           `json:"hostname,omitempty"`
	OS       osdetect.Guess   `json:"os"`
	Ports    []resultWithRisk `json:"ports"`
}

// hostScanWithRisk はホスト別出力用にリスク・OS 推定情報を添えた DTO。
type hostScanWithRisk struct {
	Host     string           `json:"host"`
	Hostname string           `json:"hostname,omitempty"`
	OS       osdetect.Guess   `json:"os"`
	Ports    []resultWithRisk `json:"ports"`
}

// enrich は各結果にリスク情報を結合する。既知リスクが無いポートは Risk=nil。
func enrich(results []scanner.Result) []resultWithRisk {
	out := make([]resultWithRisk, len(results))
	for i, r := range results {
		rw := resultWithRisk{Result: r}
		if info, ok := risk.Lookup(r.Port); ok {
			ri := info
			rw.Risk = &ri
		}
		out[i] = rw
	}
	return out
}

// Render は results を format に従って w へ書き出す（補助情報なし）。
func Render(w io.Writer, results []scanner.Result, format Format) error {
	return RenderWithMeta(w, results, format, Meta{})
}

// RenderWithMeta は mDNS 由来の補助情報 meta も加味して書き出す。
func RenderWithMeta(w io.Writer, results []scanner.Result, format Format, meta Meta) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, results, meta)
	case FormatCSV:
		return renderCSV(w, results, meta)
	default:
		return renderText(w, results, meta)
	}
}

// RenderHostScans は複数ホストのスキャン結果を format に従って w へ書き出す。
func RenderHostScans(w io.Writer, scans []HostScan, format Format) error {
	switch format {
	case FormatJSON:
		return renderHostJSON(w, scans)
	case FormatCSV:
		return renderHostCSV(w, scans)
	default:
		return renderHostText(w, scans)
	}
}

func renderHostText(w io.Writer, scans []HostScan) error {
	for _, hs := range scans {
		if _, err := fmt.Fprintf(w, "=== %s ===\n", hs.Host); err != nil {
			return err
		}
		if err := renderText(w, hs.Results, hs.Meta); err != nil {
			return err
		}
	}
	return nil
}

func renderHostJSON(w io.Writer, scans []HostScan) error {
	out := make([]hostScanWithRisk, len(scans))
	for i, hs := range scans {
		out[i] = hostScanWithRisk{
			Host:     hs.Host,
			Hostname: hs.Meta.Hostname,
			OS:       osdetect.DetectWithHints(hs.Results, osdetect.Hints{Model: hs.Meta.Model}),
			Ports:    enrich(hs.Results),
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderHostCSV(w io.Writer, scans []HostScan) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHostHeader()); err != nil {
		return err
	}
	for _, hs := range scans {
		os := osdetect.DetectWithHints(hs.Results, osdetect.Hints{Model: hs.Meta.Model})
		for _, r := range hs.Results {
			if err := cw.Write(append([]string{hs.Host}, csvRow(r, os, hs.Meta.Hostname)...)); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func renderText(w io.Writer, results []scanner.Result, meta Meta) error {
	if err := writeHostnameText(w, meta.Hostname); err != nil {
		return err
	}
	if err := writeOSText(w, osdetect.DetectWithHints(results, osdetect.Hints{Model: meta.Model})); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(w, " %d [%s]  -->   %s\n", r.Port, r.Status, r.Service); err != nil {
			return err
		}
		if r.Banner != "" {
			if _, err := fmt.Fprintf(w, "      ↳ banner: %s\n", r.Banner); err != nil {
				return err
			}
		}
		if info, ok := risk.Lookup(r.Port); ok {
			if err := writeRiskText(w, info); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeHostnameText は mDNS で得たホスト名をヘッダ行として出力する。
// 取得できていなければノイズになるため出力しない。
func writeHostnameText(w io.Writer, hostname string) error {
	if hostname == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "ホスト名: %s\n", hostname)
	return err
}

// writeOSText は推定 OS をポート一覧の前にヘッダ行として出力する。
// 手がかりが無い（unknown）場合はノイズになるため出力しない。
func writeOSText(w io.Writer, g osdetect.Guess) error {
	if !g.Known() {
		return nil
	}
	// 種別はユーザーの主関心（スマホ/PC 等）なので OS 行の前に出す。
	// 確度は OS 推定と共通のため OS 行にのみ添え、重複表示を避ける。
	if g.Device.Known() {
		if _, err := fmt.Fprintf(w, "%s: %s\n", osdetect.LabelDevice, g.Device); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s: %s  (%s: %s)\n", osdetect.LabelOS, g.OS, osdetect.LabelConfidence, g.Confidence); err != nil {
		return err
	}
	if len(g.Reasons) > 0 {
		if _, err := fmt.Fprintf(w, "  根拠: %s\n", strings.Join(g.Reasons, " / ")); err != nil {
			return err
		}
	}
	return nil
}

// writeRiskText はリスク情報を結果行の直下にインデントして併記する。
func writeRiskText(w io.Writer, info risk.Info) error {
	if _, err := fmt.Fprintf(w, "      ⚠ [%s] %s\n", info.Severity, info.Summary); err != nil {
		return err
	}
	if len(info.Attacks) > 0 {
		if _, err := fmt.Fprintf(w, "        攻撃: %s\n", strings.Join(info.Attacks, " / ")); err != nil {
			return err
		}
	}
	if len(info.Mitigations) > 0 {
		if _, err := fmt.Fprintf(w, "        対策: %s\n", strings.Join(info.Mitigations, " / ")); err != nil {
			return err
		}
	}
	return nil
}

func renderJSON(w io.Writer, results []scanner.Result, meta Meta) error {
	// nil スライスは "null" になってしまうため空配列に正規化する。
	ports := enrich(results)
	if ports == nil {
		ports = []resultWithRisk{}
	}
	out := scanReport{
		Hostname: meta.Hostname,
		OS:       osdetect.DetectWithHints(results, osdetect.Hints{Model: meta.Model}),
		Ports:    ports,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderCSV(w io.Writer, results []scanner.Result, meta Meta) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader()); err != nil {
		return err
	}
	os := osdetect.DetectWithHints(results, osdetect.Hints{Model: meta.Model})
	for _, r := range results {
		if err := cw.Write(csvRow(r, os, meta.Hostname)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func csvHeader() []string {
	// banner / os / hostname はホスト単位・任意取得なので末尾に置き、既存の列順を保つ。
	return []string{"port", "status", "service", "severity", "risk", "attacks", "mitigations", "banner", "os", "os_confidence", "hostname", "device"}
}

func csvHostHeader() []string {
	return append([]string{"host"}, csvHeader()...)
}

// csvRow は1結果を CSV の1行（ポート〜OS推定）に変換する。
// リスク未登録のポートはリスク関連列を空にする。OS 推定はホスト単位の
// 情報なので、当該ホストの全行に同じ値を繰り返し出力する。
func csvRow(r scanner.Result, os osdetect.Guess, hostname string) []string {
	row := []string{strconv.Itoa(r.Port), r.Status.String(), r.Service, "", "", "", "", r.Banner, "", "", hostname, ""}
	if info, ok := risk.Lookup(r.Port); ok {
		row[3] = info.Severity.String()
		row[4] = info.Summary
		row[5] = strings.Join(info.Attacks, " / ")
		row[6] = strings.Join(info.Mitigations, " / ")
	}
	if os.Known() {
		row[8] = os.OS
		row[9] = os.Confidence.String()
		if os.Device.Known() {
			row[11] = os.Device.String()
		}
	}
	return row
}
