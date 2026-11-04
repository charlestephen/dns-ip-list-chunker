package main

import (
	"reflect"
	"testing"
)

func TestNormalizeEntry(t *testing.T) {
	cases := []struct {
		in   string
		want string
		isIP bool
		ok   bool
	}{
		{"Example.COM.", "example.com", false, true},
		{"0.0.0.0 ads.example.com", "ads.example.com", false, true},
		{"||tracker.example.com^", "tracker.example.com", false, true},
		{"@@||allowed.example.com^", "", false, false},
		{"https://bad.example.com/path?q=1", "bad.example.com", false, true},
		{"*.wild.example.com", "wild.example.com", false, true},
		{"10.0.0.1", "10.0.0.1", true, true},
		{"10.0.0.9/8", "10.0.0.0/8", true, true},
		{"2001:db8::1", "2001:db8::1", true, true},
		{"not a domain", "", false, false},
		{"", "", false, false},
		{"999.999.999.999", "", false, false},
	}
	for _, c := range cases {
		got, isIP, ok := normalizeEntry(c.in)
		if got != c.want || isIP != c.isIP || ok != c.ok {
			t.Errorf("normalizeEntry(%q) = (%q, %v, %v), want (%q, %v, %v)", c.in, got, isIP, ok, c.want, c.isIP, c.ok)
		}
	}
}

func TestParseListFormats(t *testing.T) {
	cases := []struct {
		url  string
		body string
		dns  []string
		ips  []string
	}{
		{"https://x.test/list.txt", "# c\na.com\n0.0.0.0 b.com\n1.2.3.4\n", []string{"a.com", "b.com"}, []string{"1.2.3.4"}},
		{"https://x.test/list.txt", "10.0.0.0/8\n10.1.0.0 // note\nc.com -- x\n", []string{"c.com"}, []string{"10.0.0.0/8", "10.1.0.0"}},
		{"https://x.test/list.json", `["a.com","1.2.3.4"]`, []string{"a.com"}, []string{"1.2.3.4"}},
		{"https://x.test/list.json", "// leading\n[\"a.com\"] // trail\n", []string{"a.com"}, nil},
		{"https://x.test/list.json", `{"domains":["a.com"],"ips":["1.2.3.4"]}`, []string{"a.com"}, []string{"1.2.3.4"}},
		{"https://x.test/list.yaml", "- a.com\n- 1.2.3.4\n", []string{"a.com"}, []string{"1.2.3.4"}},
		{"https://x.test/list.yaml", "# hdr\n- a.com # item\n- \"http://b.com\"\n", []string{"a.com", "b.com"}, nil},
		{"https://x.test/list.toml", "domains = [\"a.com\"]\nips = [\"1.2.3.4\"]\n", []string{"a.com"}, []string{"1.2.3.4"}},
		{"https://x.test/list.toml", "# hdr\ndomains = [\"a.com\"] # trail\n", []string{"a.com"}, nil},
	}
	for _, c := range cases {
		dns, ips, err := parseList(c.url, "", []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if !reflect.DeepEqual(dns, c.dns) || !reflect.DeepEqual(ips, c.ips) {
			t.Errorf("%s: got dns=%v ips=%v, want dns=%v ips=%v", c.url, dns, ips, c.dns, c.ips)
		}
	}
}

func TestChunkStrings(t *testing.T) {
	got := chunkStrings([]string{"a", "b", "c", "d", "e"}, 2)
	want := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chunkStrings = %v, want %v", got, want)
	}
	if chunkStrings(nil, 5) != nil {
		t.Error("chunkStrings(nil) should be nil")
	}
}

func TestParseCSV(t *testing.T) {
	body := "domain,note\nexample.com,x\n1.2.3.4,y\n"
	dns, ips, err := parseList("https://x/list.csv", "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) != 1 || dns[0] != "example.com" {
		t.Fatalf("dns=%v", dns)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("ips=%v", ips)
	}
}
