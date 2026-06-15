// Package risk は開放ポートに対応づく代表的なセキュリティリスクの
// 組み込み静的データベースを提供する。スキャンで開いていると分かった
// ポートについて「どんな攻撃を受けうるか」「どう守るか」を提示する、
// あくまで防御・気づき目的の参考情報である。
//
// 収録内容は一般に広く知られたリスク（平文プロトコル、認証なしで公開
// されがちなデータストア、著名な CVE など）に限る。実際の脆弱性の有無は
// バージョンや構成に依存するため、本パッケージは「注意を促す」までを担い、
// 確定的な脆弱性診断は行わない。
package risk

import (
	"encoding/json"
	"fmt"
)

// Severity はリスクの深刻度。値が大きいほど深刻。
type Severity int

const (
	Low      Severity = iota // 情報露出・設定不備など、単体では影響が限定的
	Medium                   // 認証情報の盗聴や設定ミスで実害に繋がりうる
	High                     // 直接侵入・データ漏洩に繋がりやすい
	Critical                 // 無認証アクセスや著名 RCE など、即座に致命的
)

// String は深刻度の表示用文字列を返す。
func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "unknown"
	}
}

// MarshalJSON は深刻度を文字列として JSON 出力する。
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON は文字列表現の Severity を読み戻す。
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "critical":
		*s = Critical
	case "high":
		*s = High
	case "medium":
		*s = Medium
	case "low":
		*s = Low
	default:
		return fmt.Errorf("不明な Severity: %q", str)
	}
	return nil
}

// Info は1ポートに紐づくリスク情報。
type Info struct {
	Severity    Severity `json:"severity"`    // 深刻度
	Summary     string   `json:"summary"`     // リスクの一言要約
	Attacks     []string `json:"attacks"`     // 想定される代表的な攻撃・脅威
	Mitigations []string `json:"mitigations"` // 推奨される対策
}

// Lookup はポート番号に対応するリスク情報を返す。
// 既知のリスクが無いポートでは ok=false を返す。
func Lookup(port int) (Info, bool) {
	info, ok := database[port]
	return info, ok
}

// database はポート番号 → リスク情報の対応表。
// scanner.wellKnownPorts のうち、明確なリスク文脈を持つものを中心に収録する。
var database = map[int]Info{
	20: {
		Severity:    High,
		Summary:     "FTP データ転送。平文でファイルが流れ盗聴・改ざんの恐れ",
		Attacks:     []string{"通信内容の盗聴 (スニッフィング)", "中間者によるファイル改ざん"},
		Mitigations: []string{"FTPS/SFTP へ移行", "不要なら閉鎖"},
	},
	21: {
		Severity:    High,
		Summary:     "FTP 制御。認証情報が平文。匿名ログインの放置も多い",
		Attacks:     []string{"認証情報の平文盗聴", "匿名ログインによる情報露出", "総当たり攻撃"},
		Mitigations: []string{"SFTP/FTPS へ移行", "匿名ログイン無効化", "アクセス元を制限"},
	},
	22: {
		Severity:    Medium,
		Summary:     "SSH。暗号化されるが総当たり・鍵管理不備が狙われる",
		Attacks:     []string{"パスワード総当たり", "古い実装の既知脆弱性", "弱い鍵・流出鍵の悪用"},
		Mitigations: []string{"公開鍵認証のみにしパスワード認証を無効化", "fail2ban 等で試行制限", "アクセス元 IP を制限"},
	},
	23: {
		Severity:    Critical,
		Summary:     "Telnet。全通信が平文。現代では使用非推奨",
		Attacks:     []string{"認証情報を含む全通信の盗聴", "中間者攻撃", "IoT ボットネット (Mirai 等) の侵入口"},
		Mitigations: []string{"即座に無効化し SSH へ移行"},
	},
	25: {
		Severity:    Medium,
		Summary:     "SMTP。オープンリレーや平文認証が問題になりうる",
		Attacks:     []string{"オープンリレーによるスパム踏み台化", "認証情報の平文盗聴", "ユーザー列挙 (VRFY/EXPN)"},
		Mitigations: []string{"リレーを認証済みに限定", "STARTTLS を強制", "VRFY/EXPN を無効化"},
	},
	53: {
		Severity:    Medium,
		Summary:     "DNS。再帰許可やゾーン転送公開が悪用される",
		Attacks:     []string{"DNS アンプ攻撃の踏み台", "ゾーン転送 (AXFR) による内部情報漏洩", "キャッシュポイズニング"},
		Mitigations: []string{"再帰問い合わせを内部に限定", "AXFR を信頼先のみ許可", "DNSSEC の導入"},
	},
	69: {
		Severity:    High,
		Summary:     "TFTP。認証が無く誰でも読み書きしうる",
		Attacks:     []string{"設定ファイル・ファームウェアの窃取", "任意ファイルの上書き"},
		Mitigations: []string{"不要なら無効化", "アクセス元を厳格に制限"},
	},
	80: {
		Severity:    Medium,
		Summary:     "HTTP。平文。Web アプリ自体の脆弱性も入口になる",
		Attacks:     []string{"通信の盗聴・改ざん", "SQLi/XSS など Web アプリ脆弱性", "管理画面の露出"},
		Mitigations: []string{"HTTPS へリダイレクト", "WAF とパッチ適用", "管理画面のアクセス制限"},
	},
	110: {
		Severity:    Medium,
		Summary:     "POP3。平文だと認証情報・メールが盗聴される",
		Attacks:     []string{"認証情報の平文盗聴", "メール本文の盗聴"},
		Mitigations: []string{"POP3S(995) / STARTTLS を強制"},
	},
	111: {
		Severity:    Medium,
		Summary:     "RPCbind。公開すると内部サービス情報が漏れる",
		Attacks:     []string{"提供 RPC サービスの列挙", "DDoS アンプの踏み台"},
		Mitigations: []string{"外部公開を遮断", "不要なら無効化"},
	},
	119: {
		Severity:    Low,
		Summary:     "NNTP。平文認証やオープンサーバ放置に注意",
		Attacks:     []string{"認証情報の平文盗聴", "踏み台化"},
		Mitigations: []string{"TLS を有効化", "不要なら閉鎖"},
	},
	123: {
		Severity:    Medium,
		Summary:     "NTP。monlist 等のクエリが増幅攻撃に悪用される",
		Attacks:     []string{"NTP アンプ攻撃 (monlist) の踏み台"},
		Mitigations: []string{"monlist を無効化し実装を更新", "外部からのクエリを制限"},
	},
	135: {
		Severity:    High,
		Summary:     "MSRPC。Windows のリモート攻撃の入口になりやすい",
		Attacks:     []string{"DCOM/RPC 経由の既知脆弱性悪用", "横展開・列挙"},
		Mitigations: []string{"外部公開を遮断", "ファイアウォールで内部限定"},
	},
	139: {
		Severity:    High,
		Summary:     "NetBIOS。レガシー SMB 関連で情報漏洩・侵入の恐れ",
		Attacks:     []string{"共有・ユーザーの列挙", "SMB 既知脆弱性の悪用"},
		Mitigations: []string{"インターネットへの公開を遮断", "不要なら NetBIOS を無効化"},
	},
	143: {
		Severity:    Medium,
		Summary:     "IMAP。平文だと認証情報・メールが盗聴される",
		Attacks:     []string{"認証情報の平文盗聴", "メールの盗聴"},
		Mitigations: []string{"IMAPS(993) / STARTTLS を強制"},
	},
	161: {
		Severity:    High,
		Summary:     "SNMP。public 等の既定コミュニティ名放置が致命的",
		Attacks:     []string{"既定コミュニティ名での機器情報・設定の窃取", "増幅攻撃の踏み台", "設定変更 (RW 時)"},
		Mitigations: []string{"SNMPv3 で認証・暗号化", "既定コミュニティ名を変更", "外部公開を遮断"},
	},
	179: {
		Severity:    High,
		Summary:     "BGP。経路情報の改ざんは広範な影響を及ぼす",
		Attacks:     []string{"セッション乗っ取りによる経路ハイジャック", "DoS"},
		Mitigations: []string{"ピアを限定し MD5/TCP-AO で保護", "外部公開を遮断"},
	},
	389: {
		Severity:    High,
		Summary:     "LDAP。平文＋匿名バインドでディレクトリ情報が漏れる",
		Attacks:     []string{"匿名バインドによるユーザー情報の列挙", "認証情報の平文盗聴", "増幅攻撃の踏み台"},
		Mitigations: []string{"LDAPS(636) を強制", "匿名バインドを無効化", "外部公開を遮断"},
	},
	443: {
		Severity:    Low,
		Summary:     "HTTPS。暗号化されるが TLS 設定と Web アプリに注意",
		Attacks:     []string{"古い TLS/暗号スイートの悪用", "Web アプリ脆弱性 (SQLi/XSS 等)"},
		Mitigations: []string{"TLS1.2+ と強い暗号スイートに限定", "証明書とアプリのパッチ管理"},
	},
	445: {
		Severity:    Critical,
		Summary:     "SMB。EternalBlue 等の著名 RCE・ランサム横展開の主経路",
		Attacks:     []string{"EternalBlue (MS17-010) による RCE", "ランサムウェアの横展開", "共有の不正アクセス・情報窃取"},
		Mitigations: []string{"インターネットへの公開を即遮断", "SMBv1 を無効化し最新パッチ適用", "共有権限を最小化"},
	},
	465: {
		Severity:    Low,
		Summary:     "SMTPS。TLS だが認証・リレー設定に注意",
		Attacks:     []string{"認証突破によるスパム踏み台化"},
		Mitigations: []string{"認証済みリレーに限定", "強いパスワードと試行制限"},
	},
	514: {
		Severity:    Medium,
		Summary:     "Syslog。公開するとログ偽装・情報漏洩の恐れ",
		Attacks:     []string{"偽ログ注入による監査妨害", "ログ経由の内部情報漏洩"},
		Mitigations: []string{"送信元を限定 (TLS syslog 推奨)", "外部公開を遮断"},
	},
	587: {
		Severity:    Low,
		Summary:     "SMTP Submission。認証必須だがリレー設定に注意",
		Attacks:     []string{"認証突破によるスパム送信", "総当たり"},
		Mitigations: []string{"STARTTLS と認証を必須化", "試行回数を制限"},
	},
	636: {
		Severity:    Medium,
		Summary:     "LDAPS。暗号化されるが匿名バインド・公開に注意",
		Attacks:     []string{"匿名バインドによる情報列挙"},
		Mitigations: []string{"匿名バインド無効化", "アクセス元を限定"},
	},
	1080: {
		Severity:    High,
		Summary:     "SOCKS プロキシ。オープンだと踏み台にされる",
		Attacks:     []string{"オープンプロキシ悪用による匿名化・踏み台化"},
		Mitigations: []string{"認証を必須化", "アクセス元を限定", "不要なら閉鎖"},
	},
	1433: {
		Severity:    High,
		Summary:     "MS SQL Server。直接公開は侵入・情報漏洩の温床",
		Attacks:     []string{"sa アカウント等への総当たり", "弱い認証経由の RCE (xp_cmdshell)", "データ窃取"},
		Mitigations: []string{"外部公開を遮断", "強い認証と最小権限", "xp_cmdshell を無効化"},
	},
	1521: {
		Severity:    High,
		Summary:     "Oracle DB。リスナー情報露出・総当たりに注意",
		Attacks:     []string{"TNS リスナーからの情報露出", "アカウント総当たり", "データ窃取"},
		Mitigations: []string{"外部公開を遮断", "リスナーをパスワード保護", "最新パッチ適用"},
	},
	1723: {
		Severity:    High,
		Summary:     "PPTP VPN。暗号が脆弱で現代では非推奨",
		Attacks:     []string{"MS-CHAPv2 の解読による認証情報窃取", "通信の復号"},
		Mitigations: []string{"PPTP を廃止し OpenVPN/WireGuard/IKEv2 へ移行"},
	},
	2049: {
		Severity:    High,
		Summary:     "NFS。エクスポート設定不備でファイルが筒抜けに",
		Attacks:     []string{"認証なしエクスポートのマウント・情報窃取", "ファイル改ざん"},
		Mitigations: []string{"エクスポート先 IP を限定", "no_root_squash を避ける", "外部公開を遮断"},
	},
	2375: {
		Severity:    Critical,
		Summary:     "Docker API (平文)。無認証なら即ホスト乗っ取り",
		Attacks:     []string{"無認証 API からのコンテナ起動でホスト RCE", "コンテナ脱出・暗号通貨採掘の埋め込み"},
		Mitigations: []string{"TCP 公開を即停止", "TLS 相互認証 (2376) を必須化", "ローカルソケットのみ使用"},
	},
	2376: {
		Severity:    High,
		Summary:     "Docker API (TLS)。証明書管理を誤ると致命的",
		Attacks:     []string{"証明書漏洩・検証不備によるホスト乗っ取り"},
		Mitigations: []string{"相互 TLS を厳格運用", "アクセス元を限定"},
	},
	3000: {
		Severity:    Medium,
		Summary:     "開発サーバ。本番露出でデバッグ情報・RCE の恐れ",
		Attacks:     []string{"デバッグエンドポイント露出", "開発用の弱い設定悪用"},
		Mitigations: []string{"本番で公開しない", "アクセス元を限定"},
	},
	3306: {
		Severity:    High,
		Summary:     "MySQL。直接公開は総当たり・情報漏洩の温床",
		Attacks:     []string{"root 等への総当たり", "弱い認証経由のデータ窃取", "既知脆弱性の悪用"},
		Mitigations: []string{"外部公開を遮断 (bind-address を限定)", "強い認証と最小権限", "最新パッチ適用"},
	},
	3389: {
		Severity:    Critical,
		Summary:     "RDP。BlueKeep 等の RCE・総当たり・ランサムの入口",
		Attacks:     []string{"BlueKeep (CVE-2019-0708) による RCE", "総当たり・認証情報スプレー", "ランサムウェアの侵入口"},
		Mitigations: []string{"インターネットへの直接公開を遮断 (VPN/踏み台経由に)", "NLA を有効化し最新パッチ適用", "MFA と試行制限"},
	},
	5000: {
		Severity:    Medium,
		Summary:     "開発サーバ/UPnP。本番露出・UPnP 悪用に注意",
		Attacks:     []string{"デバッグ情報の露出", "UPnP 経由のポート開放悪用"},
		Mitigations: []string{"本番で公開しない", "不要な UPnP を無効化"},
	},
	5432: {
		Severity:    High,
		Summary:     "PostgreSQL。直接公開は総当たり・情報漏洩の温床",
		Attacks:     []string{"アカウント総当たり", "弱い認証経由のデータ窃取", "信頼認証 (trust) 設定の悪用"},
		Mitigations: []string{"外部公開を遮断 (listen_addresses を限定)", "pg_hba.conf を厳格化", "強い認証と最小権限"},
	},
	5672: {
		Severity:    Medium,
		Summary:     "AMQP。既定認証情報の放置・公開に注意",
		Attacks:     []string{"既定資格情報 (guest/guest) の悪用", "メッセージ盗聴・注入"},
		Mitigations: []string{"既定アカウントを無効化・変更", "TLS を有効化", "外部公開を遮断"},
	},
	5900: {
		Severity:    High,
		Summary:     "VNC。弱い/無認証だと画面操作を丸ごと奪われる",
		Attacks:     []string{"無認証・弱パスワードでの画面操作奪取", "総当たり", "通信の盗聴"},
		Mitigations: []string{"強い認証を設定", "SSH/VPN トンネル経由に限定", "外部公開を遮断"},
	},
	6379: {
		Severity:    Critical,
		Summary:     "Redis。既定で無認証。公開は即データ窃取・RCE",
		Attacks:     []string{"無認証アクセスによるデータ窃取・改ざん", "CONFIG 悪用による RCE・SSH 鍵書き込み"},
		Mitigations: []string{"requirepass で認証必須化", "bind を localhost に限定し外部公開を遮断", "protected-mode を有効化"},
	},
	8000: {
		Severity:    Medium,
		Summary:     "代替 HTTP。開発・管理用途の露出に注意",
		Attacks:     []string{"管理画面・デバッグ機能の露出", "Web アプリ脆弱性"},
		Mitigations: []string{"アクセス元を限定", "HTTPS 化とパッチ適用"},
	},
	8080: {
		Severity:    Medium,
		Summary:     "HTTP プロキシ/Tomcat。管理画面・オープンプロキシに注意",
		Attacks:     []string{"Tomcat Manager の弱認証悪用 (WAR デプロイで RCE)", "オープンプロキシ踏み台化"},
		Mitigations: []string{"管理画面を無効化/制限し強い認証", "プロキシを認証必須に", "アクセス元を限定"},
	},
	8443: {
		Severity:    Low,
		Summary:     "代替 HTTPS。管理コンソールの露出に注意",
		Attacks:     []string{"管理コンソールへの総当たり", "TLS/アプリ脆弱性"},
		Mitigations: []string{"アクセス元を限定", "強い認証とパッチ適用"},
	},
	8888: {
		Severity:    High,
		Summary:     "代替 HTTP/Jupyter。無認証 Notebook は RCE 同然",
		Attacks:     []string{"無認証 Jupyter からの任意コード実行", "管理機能の露出"},
		Mitigations: []string{"トークン/パスワード認証を必須化", "localhost バインド＋SSH トンネル", "外部公開を遮断"},
	},
	9000: {
		Severity:    Medium,
		Summary:     "SonarQube/PHP-FPM。既定認証・FastCGI 露出に注意",
		Attacks:     []string{"既定資格情報 (admin/admin) 悪用", "PHP-FPM FastCGI 直アクセスによる RCE"},
		Mitigations: []string{"既定パスワードを変更", "FPM を外部公開しない", "アクセス元を限定"},
	},
	9090: {
		Severity:    Medium,
		Summary:     "Prometheus/管理 UI。無認証だと内部情報が露出",
		Attacks:     []string{"メトリクス経由の内部構成漏洩", "管理 UI の悪用"},
		Mitigations: []string{"リバースプロキシで認証を付与", "アクセス元を限定"},
	},
	9200: {
		Severity:    Critical,
		Summary:     "Elasticsearch。既定で無認証。公開は全データ漏洩",
		Attacks:     []string{"無認証アクセスによる全インデックス窃取・削除", "ランサム的なデータ消去・身代金要求"},
		Mitigations: []string{"セキュリティ機能 (認証/TLS) を有効化", "外部公開を遮断", "アクセス元を限定"},
	},
	11211: {
		Severity:    High,
		Summary:     "Memcached。無認証＋UDP は巨大増幅攻撃の踏み台",
		Attacks:     []string{"超大規模 DDoS アンプ攻撃の踏み台", "キャッシュ内データの窃取・改ざん"},
		Mitigations: []string{"UDP を無効化", "localhost バインドし外部公開を遮断", "SASL 認証を有効化"},
	},
	27017: {
		Severity:    Critical,
		Summary:     "MongoDB。既定無認証バインドで全データ漏洩の典型例",
		Attacks:     []string{"無認証アクセスによる全コレクション窃取・削除", "ランサム的なデータ消去・身代金要求"},
		Mitigations: []string{"認証を有効化 (--auth)", "bindIp を限定し外部公開を遮断", "TLS を有効化"},
	},
	631: {
		Severity:    Medium,
		Summary:     "IPP (CUPS)。古い実装に RCE 脆弱性。公開非推奨",
		Attacks:     []string{"既知 CVE による RCE", "プリンタ情報の露出"},
		Mitigations: []string{"外部公開を遮断", "CUPS を最新化", "不要なら無効化"},
	},
	993: {
		Severity:    Low,
		Summary:     "IMAPS。暗号化されるが総当たり・古い TLS に注意",
		Attacks:     []string{"アカウント総当たり", "古い TLS/暗号スイートの悪用"},
		Mitigations: []string{"TLS1.2+ に限定", "試行回数を制限"},
	},
	995: {
		Severity:    Low,
		Summary:     "POP3S。暗号化されるが総当たり・古い TLS に注意",
		Attacks:     []string{"アカウント総当たり", "古い TLS/暗号スイートの悪用"},
		Mitigations: []string{"TLS1.2+ に限定", "試行回数を制限"},
	},
	5173: {
		Severity:    Medium,
		Summary:     "Vite 開発サーバ。本番露出はソース漏洩・RCE の恐れ",
		Attacks:     []string{"ソースコード・環境変数の露出", "既知の dev サーバ脆弱性悪用"},
		Mitigations: []string{"本番で公開しない", "アクセス元を限定"},
	},
	50021: {
		Severity:    Medium,
		Summary:     "VOICEVOX Engine。ローカル前提の API。公開非推奨",
		Attacks:     []string{"無認証 API の悪用 (リソース消費)", "想定外の外部利用"},
		Mitigations: []string{"localhost バインドのまま運用", "外部公開しない"},
	},
}
