package scanner

// wellKnownPorts は代表的なポート番号とサービス名の対応表。
// IANA 登録済みのよく使われるポートを中心に収録している。
var wellKnownPorts = map[int]string{
	20:    "FTP-DATA",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	67:    "DHCP Server",
	68:    "DHCP Client",
	69:    "TFTP",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCbind",
	119:   "NNTP",
	123:   "NTP",
	135:   "MSRPC",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	161:   "SNMP",
	179:   "BGP",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "Microsoft-DS (SMB)",
	465:   "SMTPS",
	514:   "Syslog",
	587:   "SMTP (Submission)",
	631:   "IPP (CUPS)",
	636:   "LDAPS",
	993:   "IMAPS",
	995:   "POP3S",
	1080:  "SOCKS Proxy",
	1433:  "MS SQL Server",
	1521:  "Oracle DB",
	1723:  "PPTP",
	2049:  "NFS",
	2375:  "Docker (plain)",
	2376:  "Docker (TLS)",
	3000:  "Dev Server (Node/Rails)",
	3306:  "MySQL",
	3389:  "RDP",
	5000:  "Dev Server / UPnP",
	5173:  "Vite Dev Server",
	5432:  "PostgreSQL",
	5672:  "AMQP (RabbitMQ)",
	5900:  "VNC",
	6379:  "Redis",
	8000:  "HTTP (Alt)",
	8080:  "HTTP Proxy / Tomcat",
	8443:  "HTTPS (Alt)",
	8888:  "HTTP (Alt) / Jupyter",
	9000:  "SonarQube / PHP-FPM",
	9090:  "Prometheus / Web Admin",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
	50021: "VOICEVOX Engine",
}

// DescribePort はポート番号に対応するサービス名を返す。
// 未登録のポートには "unknown" を返す。
func DescribePort(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return "unknown"
}
