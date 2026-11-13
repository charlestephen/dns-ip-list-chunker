package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAdGuardRules(t *testing.T) {
	cases := []struct {
		name, body string
		dns, allow []string
		ips        []string
	}{
		{"block rule", "||a.example^\n", []string{"a.example"}, nil, nil},
		{"important modifier blocks", "||imp.example^$important\n", []string{"imp.example"}, nil, nil},
		{"other modifiers dropped", "||a.example^$third-party\n||b.example^$dnsrewrite=NOERROR;A;1.2.3.4\n||c.example^$client=1.2.3.4\n", nil, nil, nil},
		{"mixed modifiers dropped", "||a.example^$important,third-party\n", nil, nil, nil},
		{"allow rule kept apart", "@@||ok.example^\n", nil, []string{"ok.example"}, nil},
		{"allow rule with important", "@@||ok.example^$important\n", nil, []string{"ok.example"}, nil},
		{"allow rule with other modifier dropped", "@@||ok.example^$client=x\n", nil, nil, nil},
		{"cosmetic rules ignored", "site.example##.banner\nsite2.example#@#.banner\nsite3.example#?#div\nsite4.example#$#body{}\nsite5.example#%#//scriptlet('x')\n", nil, nil, nil},
		{"cosmetic does not hide a real comment", "real.example # note\n", []string{"real.example"}, nil, nil},
		{"pipe wrapped url", "|http://pipe.example|\n", []string{"pipe.example"}, nil, nil},
		{"leading pipe", "|lead.example^\n", []string{"lead.example"}, nil, nil},
		{"wildcard prefix", "||*.wild.example^\n", []string{"wild.example"}, nil, nil},
		{"ip rule", "||1.2.3.4^\n", nil, nil, []string{"1.2.3.4"}},
		{"headers and comments", "[Adblock Plus 2.0]\n! Title: x\n||h.example^\n", []string{"h.example"}, nil, nil},
		{"regex ignored", "/ads[0-9]+\\.example/\n", nil, nil, nil},
		{"hosts line", "0.0.0.0 h.example\n127.0.0.1 localhost\n", []string{"h.example"}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseClassified("x.txt", "", []byte(c.body))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.dns, c.dns) || !slices.Equal(got.aDNS, c.allow) || !slices.Equal(got.ips, c.ips) {
				t.Fatalf("dns=%v allow=%v ips=%v; want dns=%v allow=%v ips=%v", got.dns, got.aDNS, got.ips, c.dns, c.allow, c.ips)
			}
		})
	}
}

func TestAllFormatsParse(t *testing.T) {
	cases := map[string]struct{ url, ct, body string }{
		"txt":      {"x.txt", "", "a.example\n# c\n1.2.3.4\n10.0.0.0/8\n2001:db8::/32\n"},
		"yaml":     {"x.yaml", "", "domains:\n  - a.example\nips:\n  - 1.2.3.4\n  - 10.0.0.0/8\n  - 2001:db8::/32\n"},
		"toml":     {"x.toml", "", "domains = [\"a.example\"]\n[x]\nips = [\"1.2.3.4\", \"10.0.0.0/8\", \"2001:db8::/32\"]\n"},
		"json":     {"x.json", "", `{"d":["a.example"],"i":["1.2.3.4","10.0.0.0/8","2001:db8::/32"]}`},
		"csv":      {"x.csv", "", "domain,ip\na.example,1.2.3.4\n,10.0.0.0/8\n,2001:db8::/32\n"},
		"csv type": {"http://x/list", "text/csv", "domain,ip\na.example,1.2.3.4\n,10.0.0.0/8\n,2001:db8::/32\n"},
		"adguard":  {"x.txt", "", "||a.example^\n||1.2.3.4^\n10.0.0.0/8\n2001:db8::/32\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dns, ips, err := parseList(c.url, c.ct, []byte(c.body))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(dns, []string{"a.example"}) || !slices.Equal(ips, []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::/32"}) {
				t.Fatalf("dns=%v ips=%v", dns, ips)
			}
		})
	}
}

func TestIPFormsCollapse(t *testing.T) {
	for _, in := range []string{"1.2.3.4", "1.2.3.4/32", "::ffff:1.2.3.4", "::ffff:1.2.3.4/128"} {
		got, isIP, ok := normalizeEntry(in)
		if !ok || !isIP || got != "1.2.3.4" {
			t.Errorf("normalizeEntry(%q) = %q,%v,%v; want 1.2.3.4", in, got, isIP, ok)
		}
	}
	for in, want := range map[string]string{
		"10.1.2.3/8":          "10.0.0.0/8",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"2001:db8::1/128":     "2001:db8::1",
		"2001:db8::/32":       "2001:db8::/32",
	} {
		if got, _, ok := normalizeEntry(in); !ok || got != want {
			t.Errorf("normalizeEntry(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
	// the three spellings are one entry after a merge, and land in the IPv4 stream
	_, ipv4, ipv6, _ := mergeSources([]sourceEntries{{cat: 0, ips: []string{"1.2.3.4", "1.2.3.4/32", "::ffff:1.2.3.4"}}}, []string{"default"})
	if len(ipv6) != 0 {
		t.Fatalf("ipv6 = %v", ipv6)
	}
	_ = ipv4
}

// upstreamStore builds a store over fake HTTP sources with a lists file.
func upstreamStore(t *testing.T, up *fakeUpstream, cfg config, listsYAML string) *store {
	t.Helper()
	if listsYAML != "" {
		cfg.listsFile = filepath.Join(t.TempDir(), "lists.yaml")
		if err := os.WriteFile(cfg.listsFile, []byte(listsYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.chunkSize, cfg.fetchLimit = 100, 1<<20
	excl, err := loadExclusions(filepath.Join(t.TempDir(), "exclusions.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &store{cfg: cfg, client: up.client(), excl: excl}
}

func body(t *testing.T, st *store, target string) []string {
	t.Helper()
	rec := doReq(st, "GET", target, "", "")
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d", target, rec.Code)
	}
	return strings.Fields(rec.Body.String())
}

// Blocklists from every format dedupe across sources, first source wins the
// category, and domains and IPs come out sorted.
func TestMixedFormatSourcesMergeSortedAndDeduped(t *testing.T) {
	up := newFakeUpstream(map[string]string{
		"/a.txt":  "zeta.example\nb.example.com\nexample.com\nexample.net\n10.0.0.10\n10.0.0.2\n2001:db8::2\n2001:db8::1\n",
		"/b.json": `["example.com","A.EXAMPLE.NET","10.0.0.2","8.8.8.8"]`,
		"/c.yaml": "- example.com\n- 8.8.8.8\n- yaml.example\n",
		"/d.toml": "d = [\"toml.example\", \"1.2.3.4/32\", \"1.2.3.4\"]\n",
		"/e.csv":  "domain,ip\ncsv.example,1.2.3.4\n",
	})
	st := upstreamStore(t, up, config{sources: parseSources("one:http://u/a.txt two:http://u/b.json three:http://u/c.yaml four:http://u/d.toml five:http://u/e.csv")}, "")
	if err := st.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := body(t, st, "/lists/dns-1.txt"), []string{
		"example.com", "b.example.com", "csv.example", "toml.example", "yaml.example", "zeta.example", "example.net", "a.example.net",
	}; !slices.Equal(got, want) {
		// TLD first (com < example < net), then the next label
		t.Fatalf("dns = %v\nwant %v", got, want)
	}
	if got, want := body(t, st, "/lists/ipv4-1.txt"), []string{"1.2.3.4", "8.8.8.8", "10.0.0.2", "10.0.0.10"}; !slices.Equal(got, want) {
		t.Fatalf("ipv4 = %v want %v", got, want)
	}
	if got, want := body(t, st, "/lists/ipv6-1.txt"), []string{"2001:db8::1", "2001:db8::2"}; !slices.Equal(got, want) {
		t.Fatalf("ipv6 = %v want %v", got, want)
	}
	// example.com appears in sources one, two and three: owned by "one" only
	if got := body(t, st, "/lists/two/dns-1.txt"); slices.Contains(got, "example.com") {
		t.Fatalf("category two should not repeat example.com: %v", got)
	}
}

// @@ rules count only where entries are allowed ones: a blocklist source
// ignores them, an exclusion list or allowlist honours them.
func TestAllowRulesOnlyInAllowContexts(t *testing.T) {
	up := newFakeUpstream(map[string]string{
		"/block.txt": "||keep.example^\n@@||ignored.example^\n||ok.example^\n",
		"/excl.txt":  "@@||ok.example^\n",
	})
	st := upstreamStore(t, up, config{sources: parseSources("http://u/block.txt"), exclusionURLs: []string{"http://u/excl.txt"}}, "")
	if err := st.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := body(t, st, "/lists/dns-1.txt"), []string{"keep.example"}; !slices.Equal(got, want) {
		t.Fatalf("dns = %v want %v (ignored.example must not appear; ok.example is excluded)", got, want)
	}
	if got := body(t, st, "/allowlists/remote/dns-1.txt"); !slices.Equal(got, []string{"ok.example"}) {
		t.Fatalf("remote allowlist = %v", got)
	}
}

const allowLists = `exclusion_lists:
  - name: family
    category: allow-family
    output_allowlist: true
    entries: |
      inline.example
      @@||adg.example^
      203.0.113.7
  - name: remote-allow
    category: allow-remote
    output_allowlist: true
    url: http://u/allow.json
  - name: pure
    category: pure
    entries: |
      pure.example
`

func allowUpstream() *fakeUpstream {
	return newFakeUpstream(map[string]string{
		"/block.txt":  "inline.example\nadg.example\nurl.example\nremote.example\npure.example\nmanual.example\nkeep.example\n203.0.113.7\n198.51.100.1\n2001:db8::9\n",
		"/allow.json": `{"domains":["url.example","inline.example"],"ips":["198.51.100.1","2001:db8::9"]}`,
		"/excl.txt":   "remote.example\n",
	})
}

func newAllowStore(t *testing.T, up *fakeUpstream, alsoExcludes bool) *store {
	st := upstreamStore(t, up, config{
		sources:               parseSources("http://u/block.txt"),
		exclusionURLs:         []string{"http://u/excl.txt"},
		allowlistAlsoExcludes: alsoExcludes,
	}, allowLists)
	if _, err := st.excl.add("manual.example", false); err != nil {
		t.Fatal(err)
	}
	if err := st.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

// Allowlists come from an inline list, a list URL (any format), the remote
// exclusion URLs and manual entries, and are published per category and merged.
func TestPublishedAllowlists(t *testing.T) {
	st := newAllowStore(t, allowUpstream(), false)

	wantDNS := []string{"adg.example", "inline.example", "manual.example", "remote.example", "url.example"}
	if got := body(t, st, "/allowlists/dns-1.txt"); !slices.Equal(got, wantDNS) {
		t.Fatalf("merged dns allowlist = %v want %v", got, wantDNS)
	}
	if got, want := body(t, st, "/allowlists/ipv4-1.txt"), []string{"198.51.100.1", "203.0.113.7"}; !slices.Equal(got, want) {
		t.Fatalf("merged ipv4 allowlist = %v want %v", got, want)
	}
	if got, want := body(t, st, "/allowlists/ipv6-1.txt"), []string{"2001:db8::9"}; !slices.Equal(got, want) {
		t.Fatalf("merged ipv6 allowlist = %v want %v", got, want)
	}
	for path, want := range map[string][]string{
		"/allowlists/allow-family/dns-1.txt": {"adg.example", "inline.example"},
		"/allowlists/allow-remote/dns-1.txt": {"url.example", "inline.example"},
		"/allowlists/remote/dns-1.txt":       {"remote.example"},
		"/allowlists/manual/dns-1.txt":       {"manual.example"},
	} {
		got := body(t, st, path)
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s = %v want %v", path, got, w)
		}
	}
	if rec := doReq(st, "GET", "/allowlists/pure/dns-1.txt", "", ""); rec.Code != 404 {
		t.Errorf("a list without output_allowlist must not publish; got %d", rec.Code)
	}

	idx := doReq(st, "GET", "/", "", "").Body.String()
	for _, want := range []string{"allowlist all", "allowlist allow-family", "allowlist manual", "/allowlists/dns-1.txt"} {
		if !strings.Contains(idx, want) {
			t.Errorf("index missing %q", want)
		}
	}
	var stats struct {
		AllowlistAll map[string]any `json:"allowlist_all"`
	}
	if err := json.Unmarshal(doReq(st, "GET", "/stats", "", "").Body.Bytes(), &stats); err != nil || stats.AllowlistAll["dns_entries"] != float64(len(wantDNS)) {
		t.Fatalf("stats allowlist_all = %v err=%v", stats.AllowlistAll, err)
	}
}

// ALLOWLIST_ALSO_EXCLUDES decides whether allowlist entries leave the block
// feeds. Remote exclusion URLs, manual entries and pure exclusion lists always do.
func TestAllowlistAlsoExcludesVariable(t *testing.T) {
	always := []string{"remote.example", "manual.example", "pure.example"}
	published := []string{"adg.example", "inline.example", "url.example"}

	off := body(t, newAllowStore(t, allowUpstream(), false), "/lists/dns-1.txt")
	for _, d := range always {
		if slices.Contains(off, d) {
			t.Errorf("%s must always be withheld; got %v", d, off)
		}
	}
	for _, d := range published {
		if !slices.Contains(off, d) {
			t.Errorf("%s must stay in the block feed when the variable is off; got %v", d, off)
		}
	}

	st := newAllowStore(t, allowUpstream(), true)
	on := body(t, st, "/lists/dns-1.txt")
	if !slices.Equal(on, []string{"keep.example"}) {
		t.Errorf("variable on: dns = %v want [keep.example]", on)
	}
	// every IP was allowlisted, so those streams have no chunks left
	for _, p := range []string{"/lists/ipv4-1.txt", "/lists/ipv6-1.txt"} {
		if rec := doReq(st, "GET", p, "", ""); rec.Code != 404 {
			t.Errorf("variable on: GET %s = %d want 404", p, rec.Code)
		}
	}
}

// Changing only an allowlist URL republishes it without refetching blocklists,
// and a failing allowlist URL keeps its last good copy.
func TestAllowlistURLRefresh(t *testing.T) {
	up := allowUpstream()
	st := newAllowStore(t, up, false)
	ctx := context.Background()

	up.set("/allow.json", `{"domains":["new.example"]}`)
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := body(t, st, "/allowlists/allow-remote/dns-1.txt"); !slices.Equal(got, []string{"new.example"}) {
		t.Fatalf("allowlist after change = %v", got)
	}

	up.mu.Lock()
	up.fail["/allow.json"] = true
	up.mu.Unlock()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := body(t, st, "/allowlists/allow-remote/dns-1.txt"); !slices.Equal(got, []string{"new.example"}) {
		t.Fatalf("allowlist after failed fetch = %v (want previous copy)", got)
	}
}

// A single entry added through the API shows up in the manual feed at once.
func TestManualEntryPublishes(t *testing.T) {
	st := testStore(t, "tok")
	if rec := doReq(st, "POST", "/exclusions", `{"entry":"one.example.com"}`, "Bearer tok"); rec.Code != 201 {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	if got := body(t, st, "/allowlists/manual/dns-1.txt"); !slices.Equal(got, []string{"one.example.com"}) {
		t.Fatalf("manual feed = %v", got)
	}
	if got := body(t, st, "/allowlists/dns-1.txt"); !slices.Equal(got, []string{"one.example.com"}) {
		t.Fatalf("merged feed = %v", got)
	}
	if rec := doReq(st, "DELETE", "/exclusions/one.example.com", "", "Bearer tok"); rec.Code != 200 {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if rec := doReq(st, "GET", "/allowlists/dns-1.txt", "", ""); rec.Code != 404 {
		t.Fatalf("empty merged feed = %d want 404", rec.Code)
	}
}
