// Package tui は bubbletea を用いたインタラクティブなスキャン画面を提供する。
// 進捗バーをリアルタイムに更新しつつ、検出したポートを逐次表示する。
//
// 設計の要は scanner.ScanStream のイベントを bubbletea のメッセージループへ
// 橋渡しすることにある。チャネル受信は1イベントごとに tea.Cmd 化し、
// Update で次の受信コマンドを再発行することで、UI のレンダリングと
// スキャンの進行を1本のイベントループに直列化している（共有状態のロック不要）。
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/takish/portscan/internal/risk"
	"github.com/takish/portscan/internal/scanner"
)

// メッセージ型。bubbletea は Update に届く msg の型で分岐する。
type (
	progressMsg scanner.Progress // スキャン1ポートぶんの進捗イベント
	doneMsg     struct{}         // スキャンチャネルがクローズした（完了 or 中断）
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Padding(0, 1)
	openStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	portStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("87"))
	svcStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	doneStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	hintStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	counterStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
)

// severityStyle は深刻度に応じた色付けを返す（critical=赤 … low=灰）。
func severityStyle(s risk.Severity) lipgloss.Style {
	switch s {
	case risk.Critical:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case risk.High:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	case risk.Medium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	}
}

type model struct {
	cfg      scanner.Config
	ch       <-chan scanner.Progress
	cancel   context.CancelFunc // q 押下時にスキャンを中断する
	progress progress.Model

	scanned int
	total   int
	found   []scanner.Result
	done    bool
}

// waitForEvent はチャネルから1イベント受信する tea.Cmd を返す。
// クローズ済みなら doneMsg を返す。Update 側で結果を反映するたびに
// このコマンドを再発行し、次の1件を待つ。
func waitForEvent(ch <-chan scanner.Progress) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return doneMsg{}
		}
		return progressMsg(ev)
	}
}

func (m model) Init() tea.Cmd {
	return waitForEvent(m.ch)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// 進捗バー幅を端末幅に追従させる（上限60桁で間延びを防ぐ）。
		w := msg.Width - 4
		if w > 60 {
			w = 60
		}
		if w > 0 {
			m.progress.Width = w
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			// スキャンを中断してから終了する。ctx キャンセルで
			// ワーカーが片付き、チャネルもクローズされる。
			m.cancel()
			return m, tea.Quit
		}

	case progressMsg:
		m.scanned = msg.Scanned
		m.total = msg.Total
		if msg.Found != nil {
			m.found = append(m.found, *msg.Found)
		}
		cmds := []tea.Cmd{waitForEvent(m.ch)} // 次のイベントを待つ
		if m.total > 0 {
			cmds = append(cmds, m.progress.SetPercent(float64(m.scanned)/float64(m.total)))
		}
		return m, tea.Batch(cmds...)

	case doneMsg:
		m.done = true
		cmd := m.progress.SetPercent(1.0)
		return m, cmd

	case progress.FrameMsg:
		// 進捗バーのアニメーションフレーム更新。
		pm, cmd := m.progress.Update(msg)
		m.progress = pm.(progress.Model)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	title := fmt.Sprintf(" portscan  %s  ports %d-%d ", m.cfg.Host, m.cfg.PortStart, m.cfg.PortEnd)
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	b.WriteString("  " + m.progress.View() + "\n")
	b.WriteString("  " + counterStyle.Render(fmt.Sprintf("%d/%d scanned · %d open", m.scanned, m.total, len(m.found))) + "\n\n")

	// 検出ポートは到着順（完了順）なので、表示用にコピーして昇順整列する。
	shown := make([]scanner.Result, len(m.found))
	copy(shown, m.found)
	sort.Slice(shown, func(i, j int) bool { return shown[i].Port < shown[j].Port })
	for _, r := range shown {
		line := fmt.Sprintf("  %s  %s  %s",
			portStyle.Render(fmt.Sprintf("%5d", r.Port)),
			openStyle.Render("["+r.Status.String()+"]"),
			svcStyle.Render(r.Service),
		)
		// バナーを取得していれば淡色で併記する。
		if r.Banner != "" {
			line += "  " + hintStyle.Render("("+r.Banner+")")
		}
		// 既知リスクがあれば深刻度バッジ＋要約を併記する（常に表示）。
		if info, ok := risk.Lookup(r.Port); ok {
			badge := severityStyle(info.Severity).Render("⚠ " + info.Severity.String())
			line += "  " + badge + "  " + svcStyle.Render(info.Summary)
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	if m.done {
		b.WriteString("  " + doneStyle.Render("✓ 完了") + "  " + hintStyle.Render("q で終了") + "\n")
	} else {
		b.WriteString("  " + hintStyle.Render("q / Ctrl-C で中断") + "\n")
	}
	return b.String()
}

// Run は TUI モードでスキャンを実行し、ユーザーが終了するまでブロックする。
// 結果はピプ連携の対象ではなく画面表示専用なので、altscreen を使わず
// 終了後も最終フレームが端末に残るようにしている。
func Run(ctx context.Context, cfg scanner.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch, err := scanner.ScanStream(ctx, cfg)
	if err != nil {
		return err
	}

	m := model{
		cfg:      cfg,
		ch:       ch,
		cancel:   cancel,
		progress: progress.New(progress.WithDefaultGradient()),
		total:    cfg.PortEnd - cfg.PortStart + 1,
	}

	_, err = tea.NewProgram(m).Run()
	return err
}
