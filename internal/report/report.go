// Package report はスキャン結果を各種フォーマットで出力する。
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

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
	if scans == nil {
		scans = []HostScan{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(scans)
}

func renderHostCSV(w io.Writer, scans []HostScan) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"host", "port", "status", "service"}); err != nil {
		return err
	}
	for _, hs := range scans {
		for _, r := range hs.Results {
			row := []string{hs.Host, strconv.Itoa(r.Port), r.Status.String(), r.Service}
			if err := cw.Write(row); err != nil {
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
	}
	return nil
}

func renderJSON(w io.Writer, results []scanner.Result) error {
	// nil スライスは "null" になってしまうため空配列に正規化する。
	if results == nil {
		results = []scanner.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func renderCSV(w io.Writer, results []scanner.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"port", "status", "service"}); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{strconv.Itoa(r.Port), r.Status.String(), r.Service}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
