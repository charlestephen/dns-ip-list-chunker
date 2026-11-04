package main

import (
	"os"
	"testing"
)

func TestDoubleHyphenDomainsSurviveCommentStrip(t *testing.T) {
	b, err := os.ReadFile("testdata/double-hyphen.txt")
	if err != nil {
		t.Fatal(err)
	}
	dns, ips, err := parseList("https://x/list.txt", "", b)
	if err != nil {
		t.Fatal(err)
	}
	wantDNS := map[string]bool{"ss.0001.xyz": false, "o--o.duckdns.org": false, "xn--28j2a3ar1p.died.pw": false}
	for _, d := range dns {
		if _, ok := wantDNS[d]; ok {
			wantDNS[d] = true
		}
		if d == "evil.com -- strip me" || d == "evil.com -- strip" {
			t.Fatalf("comment not stripped from %q", d)
		}
	}
	for d, ok := range wantDNS {
		if !ok {
			t.Errorf("missing %s (got %v)", d, dns)
		}
	}
	foundIP := false
	for _, ip := range ips {
		if ip == "10.0.0.0" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("ips=%v want 10.0.0.0 after // strip", ips)
	}
}
