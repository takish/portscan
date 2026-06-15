package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLabel_StripsControlAndANSI(t *testing.T) {
	// ANSI エスケープ（ESC 始まり）の ESC が除去され、注入が無効化される。
	in := "Mac\x1b[31mDevice\x1b[0m"
	got := Label(in)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("ESC が残っている: %q", got)
	}
	// 改行・タブ・DEL も除去される。
	if got := Label("a\nb\tc\x7fd"); strings.ContainsAny(got, "\n\t\x7f") {
		t.Errorf("制御文字が残っている: %q", got)
	}
}

func TestLabel_TrimsAndLimitsLength(t *testing.T) {
	if got := Label("  padded  "); got != "padded" {
		t.Errorf("前後空白が除去されていない: %q", got)
	}
	long := strings.Repeat("a", MaxLabelLen+50)
	if got := Label(long); len(got) != MaxLabelLen {
		t.Errorf("長さ制限が効いていない: len=%d want=%d", len(got), MaxLabelLen)
	}
}

func TestLabel_AlwaysValidUTF8(t *testing.T) {
	// 不正な UTF-8 バイトを含む入力でも、出力は常に妥当な UTF-8 になる。
	if got := Label("ok\xff\xfebad"); !utf8.ValidString(got) {
		t.Errorf("出力が妥当な UTF-8 でない: %q", got)
	}
	// マルチバイト文字が長さ制限の境界に来ても壊れた断片を残さない。
	multibyte := strings.Repeat("あ", MaxLabelLen) // 3バイト×N で必ず上限超過
	if got := Label(multibyte); !utf8.ValidString(got) {
		t.Errorf("境界でマルチバイトが壊れた: valid=false")
	}
}

func TestLabel_PreservesNormalText(t *testing.T) {
	// 通常のホスト名・モデル名は変化しない。
	for _, s := range []string{"Takashi-MacBook.local", "Macmini9,1", "iPhone15,2"} {
		if got := Label(s); got != s {
			t.Errorf("正常な文字列が変化した: %q -> %q", s, got)
		}
	}
}
