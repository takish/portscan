// Package sanitize は外部（ネットワーク等）由来の信頼できない文字列を、
// 端末へ出力する前に無害化するユーティリティを提供する。
//
// mDNS 応答やサービスバナーは同一セグメントの第三者が任意に偽装できるため、
// ANSI エスケープなどの制御シーケンス注入をここ1箇所で防ぐ。無害化の口を
// 集約することで、新しい外部入力経路が増えても適用漏れに気づきやすくする。
package sanitize

import "strings"

// MaxLabelLen は保持するラベル/バナーの最大バイト長。過大・悪意ある応答で
// メモリや表示を圧迫しないよう切り詰める。
const MaxLabelLen = 256

// Label は信頼できない文字列を端末出力に適した形へ無害化する:
//   - 制御文字（C0 制御と DEL。ESC=0x1b を含む）を除去し ANSI 等の注入を防ぐ
//   - 前後の空白を除去し、MaxLabelLen バイトへ切り詰める
//   - 切り詰めや不正バイトで生じた無効な UTF-8 を除去する
func Label(s string) string {
	// 制御文字を除去する。不正な UTF-8 バイトはこの時点で U+FFFD に置換される。
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > MaxLabelLen {
		s = s[:MaxLabelLen]
	}
	// 切り詰めで末尾に生じうる不完全なマルチバイト断片を取り除く。
	return strings.ToValidUTF8(s, "")
}
