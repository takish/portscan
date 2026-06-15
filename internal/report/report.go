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

// HostScan は1台のホストに対するスキャン結果を表す。
type HostScan struct {
	Host    string           `json:"host"`
	Results []scanner.Result `json:"ports"`
}

// resultWithRisk は1ポートの結果にリスク情報を添えた出力用 DTO。
// scanner.Result を埋め込み、その JSON フィールド(port/status/service)を
// 引き継ぎつつ risk を付加する。
type resultWithRisk struct {
	scanner.Result
	Risk *risk.Info `json:"risk,omitempty"`
}

// hostScanWithRisk はホスト別出力用にリスク情報を添えた DTO。
type hostScanWithRisk struct {
	Host  string           `json:"host"`
	Ports []resultWithRisk `json:"ports"`
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

// Render は results を format に従って w へ書き出す。
func Render(w io.Writer, results []scanner.Result, format Format) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, results)
	case FormatCSV:
		return renderCSV(w, results)
	default:
		return renderText(w, results)
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
		if err := renderText(w, hs.Results); err != nil {
			return err
		}
	}
	return nil
}

func renderHostJSON(w io.Writer, scans []HostScan) error {
	out := make([]hostScanWithRisk, len(scans))
	for i, hs := range scans {
		out[i] = hostScanWithRisk{Host: hs.Host, Ports: enrich(hs.Results)}
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
		for _, r := range hs.Results {
			if err := cw.Write(append([]string{hs.Host}, csvRow(r)...)); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func renderText(w io.Writer, results []scanner.Result) error {
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

func renderJSON(w io.Writer, results []scanner.Result) error {
	// nil スライスは "null" になってしまうため空配列に正規化する。
	out := enrich(results)
	if out == nil {
		out = []resultWithRisk{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderCSV(w io.Writer, results []scanner.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader()); err != nil {
		return err
	}
	for _, r := range results {
		if err := cw.Write(csvRow(r)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func csvHeader() []string {
	// banner は任意取得（-banner 時のみ）なので末尾に置き、既存の列順を保つ。
	return []string{"port", "status", "service", "severity", "risk", "attacks", "mitigations", "banner"}
}

func csvHostHeader() []string {
	return append([]string{"host"}, csvHeader()...)
}

// csvRow は1結果を CSV の1行（ポート〜対策）に変換する。
// リスク未登録のポートはリスク関連列を空にする。
func csvRow(r scanner.Result) []string {
	row := []string{strconv.Itoa(r.Port), r.Status.String(), r.Service, "", "", "", "", r.Banner}
	if info, ok := risk.Lookup(r.Port); ok {
		row[3] = info.Severity.String()
		row[4] = info.Summary
		row[5] = strings.Join(info.Attacks, " / ")
		row[6] = strings.Join(info.Mitigations, " / ")
	}
	return row
}
