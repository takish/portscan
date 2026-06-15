package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/takish/portscan/internal/scanner"
)

// newTestModel は受信チャネル無しでロジック検証用のモデルを組み立てる。
// （Update は progressMsg/doneMsg を直接流して状態遷移を確かめる）
func newTestModel(total int) model {
	return model{
		cfg:      scanner.Config{Host: "127.0.0.1", PortStart: 1, PortEnd: total},
		progress: progress.New(),
		total:    total,
	}
}

func TestModel_ProgressUpdatesState(t *testing.T) {
	m := newTestModel(10)

	found := scanner.Result{Port: 80, Status: scanner.StatusOpen, Service: "HTTP"}
	next, _ := m.Update(progressMsg{Scanned: 3, Total: 10, Found: &found})
	m = next.(model)

	if m.scanned != 3 {
		t.Errorf("scanned=%d, want 3", m.scanned)
	}
	if len(m.found) != 1 || m.found[0].Port != 80 {
		t.Errorf("found が反映されていない: %+v", m.found)
	}
}

func TestModel_FoundSortedInView(t *testing.T) {
	m := newTestModel(100)
	// 到着順はバラバラ（80 → 22）でも View では昇順に並ぶこと。
	for _, p := range []int{80, 22} {
		r := scanner.Result{Port: p, Status: scanner.StatusOpen, Service: "x"}
		next, _ := m.Update(progressMsg{Scanned: p, Total: 100, Found: &r})
		m = next.(model)
	}
	view := m.View()
	i22 := strings.Index(view, "22")
	i80 := strings.Index(view, "80")
	if i22 < 0 || i80 < 0 || i22 > i80 {
		t.Errorf("View でポートが昇順に並んでいない (22@%d, 80@%d):\n%s", i22, i80, view)
	}
}

func TestModel_MDNSResultUpdatesView(t *testing.T) {
	m := newTestModel(10)
	m.useMDNS = true

	// 収集完了前は「mDNS 収集中…」が出る。
	if !strings.Contains(m.View(), "mDNS 収集中") {
		t.Errorf("収集中表示が出ていない:\n%s", m.View())
	}

	// mDNS 結果（モデル付き）を流すとホスト名表示＋OS 推定に反映される。
	next, _ := m.Update(mdnsResultMsg{hostname: "Mac.local", model: "Macmini9,1"})
	m = next.(model)
	view := m.View()
	if !strings.Contains(view, "ホスト名: Mac.local") {
		t.Errorf("ホスト名が表示されていない:\n%s", view)
	}
	// モデルヒントで OS は macOS(high) になる。
	if !strings.Contains(view, "推定OS: macOS") {
		t.Errorf("mDNS モデルが OS 推定に効いていない:\n%s", view)
	}
	if strings.Contains(view, "mDNS 収集中") {
		t.Errorf("完了後も収集中表示が残っている:\n%s", view)
	}
}

func TestModel_DoneSetsFlag(t *testing.T) {
	m := newTestModel(10)
	next, _ := m.Update(doneMsg{})
	m = next.(model)
	if !m.done {
		t.Error("doneMsg 後に done が true になっていない")
	}
	if !strings.Contains(m.View(), "完了") {
		t.Errorf("完了表示が出ていない:\n%s", m.View())
	}
}

func TestModel_QuitCancelsAndQuits(t *testing.T) {
	cancelled := false
	m := newTestModel(10)
	m.cancel = func() { cancelled = true }

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	_ = next
	if !cancelled {
		t.Error("q 押下で cancel が呼ばれていない")
	}
	if cmd == nil {
		t.Fatal("q 押下で tea.Quit コマンドが返るべき")
	}
	// 返ったコマンドを実行すると QuitMsg になること。
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("返ったコマンドが tea.Quit ではない")
	}
}
