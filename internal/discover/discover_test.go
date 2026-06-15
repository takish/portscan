package discover

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestHosts(t *testing.T) {
	// /30 は 4 アドレス。ネットワーク(.0)とブロードキャスト(.3)を除いた2つ。
	got, err := Hosts("192.168.1.0/30")
	if err != nil {
		t.Fatalf("Hosts が失敗: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts(/30)=%v, want %v", got, want)
	}
}

func TestHosts_TooWide(t *testing.T) {
	// /8 はホスト空間が大きすぎるため拒否されること。
	if _, err := Hosts("10.0.0.0/8"); err == nil {
		t.Error("広すぎる CIDR でエラーが返るべき")
	}
}

func TestHosts_Invalid(t *testing.T) {
	if _, err := Hosts("not-a-cidr"); err == nil {
		t.Error("不正な CIDR でエラーが返るべき")
	}
}

func TestIsUp_RefusedIsAlive(t *testing.T) {
	// localhost は probePorts が閉じていても「接続拒否」が返るため生存扱い。
	// （ループバックは確実に到達でき、閉ポートは即 refused になる）
	if !IsUp(context.Background(), "127.0.0.1", time.Second) {
		t.Error("localhost は生存と判定されるべき（refused でも到達可能）")
	}
}

func TestIsUp_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if IsUp(ctx, "127.0.0.1", time.Second) {
		t.Error("キャンセル済み context では false を返すべき")
	}
}
