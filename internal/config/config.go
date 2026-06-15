// Package config はよく使うスキャン設定を JSON ファイルへ保存・読込する。
// 追加依存を避けたいので YAML 等は使わず標準ライブラリの encoding/json のみ。
//
// 設計の要は「フラグが設定ファイルより優先」を正しく実現することにある。
// flag パッケージは未指定でもデフォルト値を持つため、値の比較では「ユーザーが
// 明示したか」を判別できない。そこで Parse 後に flag.Visit で明示指定された
// フラグ名だけを集め、それ以外のフラグにのみ設定ファイルの値を流し込む。
package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config は設定ファイルの内容を表す。各フィールドはポインタで、
// JSON に存在したキーだけが非 nil になる（未指定はフラグ既定値を温存する）。
type Config struct {
	Host         *string `json:"host,omitempty"`
	Start        *int    `json:"start,omitempty"`
	End          *int    `json:"end,omitempty"`
	Threads      *int    `json:"threads,omitempty"`
	Timeout      *string `json:"timeout,omitempty"` // "2s" のような duration 文字列
	Format       *string `json:"format,omitempty"`
	ShowFiltered *bool   `json:"show_filtered,omitempty"`
	Banner       *bool   `json:"banner,omitempty"`
	Discover     *bool   `json:"discover,omitempty"`
	CIDR         *string `json:"cidr,omitempty"`
	TUI          *bool   `json:"tui,omitempty"`
	Mdns         *bool   `json:"mdns,omitempty"`
}

// DefaultPaths は -config 無指定時に順に探索する設定ファイルのパスを返す。
// カレントディレクトリ優先、次にユーザー設定ディレクトリ配下。
func DefaultPaths() []string {
	paths := []string{"portscan.json"}
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "portscan", "config.json"))
	}
	return paths
}

// Load は設定ファイルを読み込む。
//   - explicit が非空: そのパスを読む。存在しなければエラー（指定ミスを見逃さない）。
//   - explicit が空 : DefaultPaths を順に探し、最初に見つかったものを読む。
//     どれも無ければ空 Config と空パスを返す（エラーにしない）。
//
// 戻り値の2番目は実際に読んだパス（探索結果の可視化用。未使用時は空文字列）。
func Load(explicit string) (Config, string, error) {
	if explicit != "" {
		c, err := readFile(explicit)
		return c, explicit, err
	}
	for _, p := range DefaultPaths() {
		if _, err := os.Stat(p); err == nil {
			c, err := readFile(p)
			return c, p, err
		}
	}
	return Config{}, "", nil
}

func readFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("設定ファイルの読込に失敗: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // 設定ミス（typo したキー）を黙って無視しない
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("設定ファイルの解析に失敗 (%s): %w", path, err)
	}
	return c, nil
}

// Save は設定を JSON（インデント付き）でパスへ書き出す。
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("設定の JSON 化に失敗: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("設定ファイルの書込に失敗: %w", err)
	}
	return nil
}

// ApplyTo は設定ファイルの値を、明示指定されていないフラグにのみ適用する。
// explicit には flag.Visit で集めた「明示指定されたフラグ名」を渡す。
// これにより優先順位は「コマンドラインフラグ ＞ 設定ファイル ＞ フラグ既定値」になる。
func (c Config) ApplyTo(fs *flag.FlagSet, explicit map[string]bool) error {
	set := func(name, val string) error {
		if explicit[name] {
			return nil // フラグが明示指定されていれば設定ファイルでは上書きしない
		}
		if fs.Lookup(name) == nil {
			return nil // FlagSet に存在しないフラグ名は無視する
		}
		if err := fs.Set(name, val); err != nil {
			return fmt.Errorf("設定値 %s=%q の適用に失敗: %w", name, val, err)
		}
		return nil
	}

	if c.Host != nil {
		if err := set("host", *c.Host); err != nil {
			return err
		}
	}
	if c.Start != nil {
		if err := set("start", strconv.Itoa(*c.Start)); err != nil {
			return err
		}
	}
	if c.End != nil {
		if err := set("end", strconv.Itoa(*c.End)); err != nil {
			return err
		}
	}
	if c.Threads != nil {
		if err := set("threads", strconv.Itoa(*c.Threads)); err != nil {
			return err
		}
	}
	if c.Timeout != nil {
		if err := set("timeout", *c.Timeout); err != nil {
			return err
		}
	}
	if c.Format != nil {
		if err := set("format", *c.Format); err != nil {
			return err
		}
	}
	if c.ShowFiltered != nil {
		if err := set("show-filtered", strconv.FormatBool(*c.ShowFiltered)); err != nil {
			return err
		}
	}
	if c.Banner != nil {
		if err := set("banner", strconv.FormatBool(*c.Banner)); err != nil {
			return err
		}
	}
	if c.Discover != nil {
		if err := set("discover", strconv.FormatBool(*c.Discover)); err != nil {
			return err
		}
	}
	if c.CIDR != nil {
		if err := set("cidr", *c.CIDR); err != nil {
			return err
		}
	}
	if c.TUI != nil {
		if err := set("tui", strconv.FormatBool(*c.TUI)); err != nil {
			return err
		}
	}
	if c.Mdns != nil {
		if err := set("mdns", strconv.FormatBool(*c.Mdns)); err != nil {
			return err
		}
	}
	return nil
}
