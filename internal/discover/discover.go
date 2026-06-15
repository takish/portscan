// Package discover はローカルネットワークの生存ホスト探索（ホストディスカバリ）を提供する。
// ICMP の代わりに TCP ピングを用いるため root 権限を必要とせず、外部依存もない。
package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// maxHosts は一度に列挙するホスト数の上限。巨大な CIDR による暴走を防ぐ。
const maxHosts = 65536

// probePorts は生存確認に用いる代表的なポート。いずれかが応答すれば生存とみなす。
var probePorts = []int{80, 443, 22, 445, 3389, 8080}

// LocalCIDR はマシンのプライマリなプライベート IPv4 インターフェースの
// CIDR（例 "192.168.1.0/24"）を返す。
func LocalCIDR() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		// 停止中・ループバックのインターフェースは対象外。
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsPrivate() {
				continue
			}
			network := ip4.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			return fmt.Sprintf("%s/%d", network.String(), ones), nil
		}
	}
	return "", errors.New("プライベート IPv4 インターフェースが見つかりません")
}

// Hosts は CIDR 内の利用可能なホスト IP を列挙する。
// IPv4 ではネットワークアドレスとブロードキャストアドレスを除外する。
func Hosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// 列挙数が上限を超える場合は拒否する。
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 { // 2^16 を超えるホスト空間は許可しない
		return nil, fmt.Errorf("CIDR が広すぎます (/%d)。/%d 以上を指定してください", ones, bits-16)
	}

	var ips []string
	for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) > maxHosts {
			return nil, fmt.Errorf("ホスト数が上限 %d を超えました", maxHosts)
		}
	}
	// IPv4 で2つ以上あれば先頭（ネットワーク）と末尾（ブロードキャスト）を除く。
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// IsUp は host が生存しているかを TCP ピングで判定する。
// 代表ポートに順に接続を試み、接続成功または「接続拒否」が返れば生存とみなす。
// タイムアウトのみが続いた場合は不在とみなす。
func IsUp(ctx context.Context, host string, timeout time.Duration) bool {
	for _, p := range probePorts {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			_ = conn.Close()
			return true // ポート開放 → 確実に生存
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return true // 接続拒否 → 相手は応答しているので生存
		}
		// タイムアウトやその他のエラーは判定保留。次のポートを試す。
	}
	return false
}

// Discover は CIDR 内の生存ホストを並列に探索し、IP 昇順で返す。
// ctx のキャンセルで途中終了でき、その場合は ctx.Err() を返す。
func Discover(ctx context.Context, cidr string, threads int, timeout time.Duration) ([]string, error) {
	hosts, err := Hosts(cidr)
	if err != nil {
		return nil, err
	}
	if threads < 1 {
		threads = 1
	}
	if threads > len(hosts) {
		threads = len(hosts)
	}

	in := make(chan string)
	out := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range in {
				if IsUp(ctx, h, timeout) {
					out <- h
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case in <- h:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var live []string
	for h := range out {
		live = append(live, h)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(live, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(live[i]).To16(), net.ParseIP(live[j]).To16()) < 0
	})
	return live, nil
}

// inc は IP アドレスを1つ進める（バイト列のインクリメント）。
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// cloneIP は IP のコピーを返す（元の ipnet を破壊しないため）。
func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}
