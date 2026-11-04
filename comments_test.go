package main

import "testing"

func TestStripLineComment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.0/0", "10.0.0.0/0"},
		{"10.0.0.0 //00", "10.0.0.0"},
		{"10.0.0.0 -- note", "10.0.0.0"},
		{"evil.com # tracker", "evil.com"},
		{"evil.com; comment", "evil.com"},
		{`{"url":"http://example.com"}`, `{"url":"http://example.com"}`},
		{`key = "http://x.test" # trail`, `key = "http://x.test"`},
		{`key = 'http://x.test' # trail`, `key = 'http://x.test'`},
		{"# full line", ""},
		{"-- full line", ""},
		{"// full line", ""},
		{"0.0.0.0 ads.example.com # hosts", "0.0.0.0 ads.example.com"},
		// Double-hyphen / slash inside labels must NOT be comments.
		{"o--o.duckdns.org", "o--o.duckdns.org"},
		{"xn--28j2a3ar1p.died.pw", "xn--28j2a3ar1p.died.pw"},
		{"asbouyo-----ya.easterndns.com", "asbouyo-----ya.easterndns.com"},
		{"http://example.com/path", "http://example.com/path"},
	}
	for _, c := range cases {
		if got := stripLineComment(c.in); got != c.want {
			t.Errorf("stripLineComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseSource(t *testing.T) {
	cases := []struct {
		in, cat, url string
	}{
		{"https://x.test/list.txt", "default", "https://x.test/list.txt"},
		{"threat:https://x.test/list.txt", "threat", "https://x.test/list.txt"},
		{"Threat Intelligence:https://x.test/a.txt", "threat-intelligence", "https://x.test/a.txt"},
		{"dns-blocklisting:http://x.test/b.txt", "dns-blocklisting", "http://x.test/b.txt"},
		{"  threat:https://x.test/c.txt  ", "threat", "https://x.test/c.txt"},
	}
	for _, c := range cases {
		got := parseSource(c.in)
		if got.Category != c.cat || got.URL != c.url {
			t.Errorf("parseSource(%q) = %+v, want cat=%q url=%q", c.in, got, c.cat, c.url)
		}
	}
}

func TestNormalizeCategory(t *testing.T) {
	if got := normalizeCategory("Threat Intelligence"); got != "threat-intelligence" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeCategory("  "); got != "default" {
		t.Fatalf("got %q", got)
	}
}
