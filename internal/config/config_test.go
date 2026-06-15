package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }
func boolptr(b bool) *bool    { return &b }

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")

	want := Config{
		Host:    strptr("example.com"),
		Start:   intptr(1),
		End:     intptr(1024),
		Threads: intptr(200),
		Timeout: strptr("1s"),
		Format:  strptr("json"),
		Banner:  boolptr(true),
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}

	got, srcPath, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if srcPath != path {
		t.Errorf("srcPath=%q, want %q", srcPath, path)
	}
	if got.Host == nil || *got.Host != "example.com" || got.Threads == nil || *got.Threads != 200 {
		t.Errorf("ラウンドトリップ不一致: %+v", got)
	}
	if got.Banner == nil || !*got.Banner {
		t.Errorf("Banner が復元されない: %+v", got)
	}
}

func TestLoad_ExplicitMissing(t *testing.T) {
	// 明示指定したパスが存在しなければエラー（指定ミスを見逃さない）。
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("存在しない明示パスでエラーが返るべき")
	}
}

func TestLoad_AutoDiscoverNoneIsNotError(t *testing.T) {
	// 自動探索でどれも見つからなくてもエラーにしない。
	// カレントに portscan.json が無い一時ディレクトリで検証する。
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir 失敗: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	// UserConfigDir 配下を一時的に空ディレクトリへ向け、誤検出を防ぐ。
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg-empty"))
	t.Setenv("HOME", dir)

	c, path, err := Load("")
	if err != nil {
		t.Fatalf("自動探索でエラー: %v", err)
	}
	if path != "" || c.Host != nil {
		t.Errorf("未発見なのに値が返った: path=%q cfg=%+v", path, c)
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"hostt": "typo"}`), 0o644); err != nil {
		t.Fatalf("WriteFile 失敗: %v", err)
	}
	if _, _, err := Load(path); err == nil {
		t.Error("未知キーを含む設定でエラーが返るべき")
	}
}

func TestApplyTo_FlagOverridesConfig(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	host := fs.String("host", "localhost", "")
	threads := fs.Int("threads", 100, "")
	banner := fs.Bool("banner", false, "")

	// host は明示指定、threads/banner は未指定という状況を模す。
	if err := fs.Parse([]string{"-host", "cli.example"}); err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	cfg := Config{
		Host:    strptr("file.example"), // 明示フラグがあるので無視されるべき
		Threads: intptr(256),            // 未指定なので適用されるべき
		Banner:  boolptr(true),          // 未指定なので適用されるべき
	}
	if err := cfg.ApplyTo(fs, explicit); err != nil {
		t.Fatalf("ApplyTo 失敗: %v", err)
	}

	if *host != "cli.example" {
		t.Errorf("host=%q, want cli.example（フラグが優先されるべき）", *host)
	}
	if *threads != 256 {
		t.Errorf("threads=%d, want 256（設定ファイルが適用されるべき）", *threads)
	}
	if !*banner {
		t.Errorf("banner=%v, want true（設定ファイルが適用されるべき）", *banner)
	}
}

func TestApplyTo_InvalidValueErrors(t *testing.T) {
	// timeout フラグが Duration として定義されている場合、不正な値はエラーになる。
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Duration("timeout", 0, "")
	_ = fs.Parse(nil)

	cfg := Config{Timeout: strptr("not-a-duration")}
	if err := cfg.ApplyTo(fs, map[string]bool{}); err == nil {
		t.Error("不正な duration でエラーが返るべき")
	}
}

func TestApplyTo_UnknownFlagIgnored(t *testing.T) {
	// FlagSet に存在しないフラグ名のキーは無視する（エラーにしない）。
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Int("threads", 100, "")
	_ = fs.Parse(nil)

	cfg := Config{Timeout: strptr("2s")} // timeout フラグは未定義
	if err := cfg.ApplyTo(fs, map[string]bool{}); err != nil {
		t.Errorf("未定義フラグのキーは無視されるべき: %v", err)
	}
}
