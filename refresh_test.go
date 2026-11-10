package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// refDomainCompare is the original allocating comparator, kept as the
// reference the optimized sort and compare must agree with.
func refDomainCompare(a, b string) int {
	if a == b {
		return 0
	}
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 1; ; i++ {
		aOK, bOK := i <= len(ap), i <= len(bp)
		switch {
		case !aOK && !bOK:
			return 0
		case !aOK:
			return -1
		case !bOK:
			return 1
		}
		if al, bl := ap[len(ap)-i], bp[len(bp)-i]; al != bl {
			return strings.Compare(al, bl)
		}
	}
}

func randomDomains(n int, seed int64) []string {
	r := rand.New(rand.NewSource(seed))
	// Few distinct labels, including prefixes of each other and hyphens, so
	// ties, parents and "a" vs "a-b" cases are hit constantly.
	labels := []string{"a", "a-b", "a-", "b", "ab", "xn--a", "x", "0", "9a", "com", "co", "uk", "net"}
	out := make([]string, n)
	for i := range out {
		parts := make([]string, 1+r.Intn(4))
		for j := range parts {
			parts[j] = labels[r.Intn(len(labels))]
		}
		out[i] = strings.Join(parts, ".")
	}
	return out
}

func TestDomainCompareMatchesReference(t *testing.T) {
	ds := randomDomains(400, 1)
	for _, a := range ds {
		for _, b := range ds {
			if got, want := domainCompare(a, b), refDomainCompare(a, b); got != want {
				t.Fatalf("domainCompare(%q,%q)=%d, reference %d", a, b, got, want)
			}
		}
	}
}

func TestSortDomainsMatchesReference(t *testing.T) {
	for seed := int64(0); seed < 5; seed++ {
		in := randomDomains(3000, seed)
		want := slices.Clone(in)
		slices.SortStableFunc(want, refDomainCompare)
		got := slices.Clone(in)
		sortDomains(got)
		if !slices.Equal(got, want) {
			t.Fatalf("seed %d: sortDomains order differs from reference", seed)
		}
		// Sorting sorted input is a no-op.
		again := slices.Clone(got)
		sortDomains(again)
		if !slices.Equal(again, got) {
			t.Fatalf("seed %d: re-sort changed sorted input", seed)
		}
	}
}

func TestDomainKeyOrderMatchesCompare(t *testing.T) {
	ds := randomDomains(300, 7)
	for _, a := range ds {
		for _, b := range ds {
			if got, want := strings.Compare(domainKey(a), domainKey(b)), refDomainCompare(a, b); got != want {
				t.Fatalf("key order(%q,%q)=%d, reference %d", a, b, got, want)
			}
		}
	}
}

func TestSortIPsMatchesPairwiseCompare(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	var in []string
	for i := 0; i < 3000; i++ {
		switch r.Intn(4) {
		case 0:
			in = append(in, fmt.Sprintf("%d.%d.0.0/%d", r.Intn(4), r.Intn(4), 8+r.Intn(3)*8))
		case 1:
			in = append(in, fmt.Sprintf("%d.%d.%d.%d", r.Intn(3), r.Intn(3), r.Intn(3), r.Intn(3)))
		case 2:
			in = append(in, fmt.Sprintf("2001:db8:%x::/%d", r.Intn(4), 32+r.Intn(3)*16))
		default:
			in = append(in, fmt.Sprintf("::ffff:%d.%d.0.1", r.Intn(3), r.Intn(3)))
		}
	}
	got := slices.Clone(in)
	sortIPs(got)
	if !slices.IsSortedFunc(got, ipCompare) {
		t.Fatal("sortIPs output not ordered by ipCompare")
	}
	if len(got) != len(in) {
		t.Fatal("sortIPs lost entries")
	}
}

func TestFirstTwoFields(t *testing.T) {
	cases := []struct {
		in   string
		a, b string
		n    int
	}{
		{"", "", "", 0},
		{"   ", "", "", 0},
		{"a.com", "a.com", "", 1},
		{"  a.com  ", "a.com", "", 1},
		{"0.0.0.0 a.com", "0.0.0.0", "a.com", 2},
		{"0.0.0.0\ta.com\tx y", "0.0.0.0", "a.com", 2},
		{"a.com b.com", "a.com", "b.com", 2}, // non-ASCII space: stdlib rules
	}
	for _, c := range cases {
		a, b, n := firstTwoFields(c.in)
		if a != c.a || b != c.b || n != c.n {
			t.Errorf("firstTwoFields(%q)=(%q,%q,%d), want (%q,%q,%d)", c.in, a, b, n, c.a, c.b, c.n)
		}
	}
}

func TestStripCommentsFastPathAndSlowPath(t *testing.T) {
	clean := []byte(`["a.com","b.com"]`)
	if got := stripComments(clean); &got[0] != &clean[0] {
		t.Fatal("comment-free body should be returned untouched")
	}
	got := string(stripComments([]byte("[\"a.com\"] // x\n# y\n")))
	if got != "[\"a.com\"]\n\n" {
		t.Fatalf("stripComments = %q", got)
	}
}

func TestCSVFallsBackToText(t *testing.T) {
	// A bare quote in the middle of a field is tolerated (LazyQuotes), so
	// this exercises the normal streaming path with messy input.
	dns, ips, err := parseList("https://x/l.csv", "", []byte("ip,score\n1.2.3.4,9\nbad\"quote.com,1\nexample.org,2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ips, []string{"1.2.3.4"}) || !slices.Contains(dns, "example.org") {
		t.Fatalf("dns=%v ips=%v", dns, ips)
	}
}

// --- mergeSources ---

func TestMergeSourcesFirstWinsSortedDeduped(t *testing.T) {
	srcs := []sourceEntries{
		{cat: 0, dns: []string{"z.example.com", "shared.example.com", "b.net"}, ips: []string{"10.0.0.0/8", "2001:db8::/32", "::ffff:1.2.3.4"}},
		{cat: 1, dns: []string{"shared.example.com", "a.net", "b.net"}, ips: []string{"10.0.0.0/8", "9.9.9.9"}},
		{cat: 0, dns: []string{"a.net"}}, // same category again, lower priority
	}
	dns, v4, v6, cats := mergeSources(srcs, []string{"threat", "ads"})

	wantAll := []string{"shared.example.com", "z.example.com", "a.net", "b.net"} // root-first: com before net
	if !slices.Equal(dns, wantAll) {
		t.Fatalf("dns = %v, want %v", dns, wantAll)
	}
	// IPv4 stream: numeric order, with the IPv4-mapped form unmapped.
	if len(v4) != 3 || v4[0] != "::ffff:1.2.3.4" || v4[1] != "9.9.9.9" || v4[2] != "10.0.0.0/8" {
		t.Fatalf("ipv4 = %v", v4)
	}
	if !slices.Equal(v6, []string{"2001:db8::/32"}) {
		t.Fatalf("ipv6 = %v", v6)
	}
	// First source wins: shared.example.com and b.net belong to "threat".
	if !slices.Equal(cats["threat"].dnsAll, []string{"shared.example.com", "z.example.com", "b.net"}) {
		t.Fatalf("threat dns = %v", cats["threat"].dnsAll)
	}
	if !slices.Equal(cats["ads"].dnsAll, []string{"a.net"}) {
		t.Fatalf("ads dns = %v", cats["ads"].dnsAll)
	}
	if !slices.Equal(cats["ads"].ipv4All, []string{"9.9.9.9"}) {
		t.Fatalf("ads ipv4 = %v", cats["ads"].ipv4All)
	}
	// Every category slice stays sorted without a second sort.
	for name, c := range cats {
		if !slices.IsSortedFunc(c.dnsAll, domainCompare) || !slices.IsSortedFunc(c.ipv4All, ipCompare) {
			t.Fatalf("category %s not sorted", name)
		}
	}
}

// --- conditional refresh ---

// fakeUpstream serves bodies with ETags and counts full downloads.
type fakeUpstream struct {
	mu     sync.Mutex
	bodies map[string]string
	rev    map[string]int
	full   int
	cond   int
	fail   map[string]bool
}

func newFakeUpstream(bodies map[string]string) *fakeUpstream {
	return &fakeUpstream{bodies: bodies, rev: map[string]int{}, fail: map[string]bool{}}
}

func (f *fakeUpstream) set(path, body string) {
	f.mu.Lock()
	f.bodies[path] = body
	f.rev[path]++
	f.mu.Unlock()
}

func (f *fakeUpstream) client() *http.Client {
	return &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		mk := func(code int, body string) *http.Response {
			return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d x", code), Header: http.Header{"Etag": {fmt.Sprintf(`"%s-%d"`, p, f.rev[p])}},
				Body: io.NopCloser(strings.NewReader(body)), Request: r}
		}
		if f.fail[p] {
			return mk(500, ""), nil
		}
		etag := fmt.Sprintf(`"%s-%d"`, p, f.rev[p])
		if r.Header.Get("If-None-Match") == etag {
			f.cond++
			return mk(304, ""), nil
		}
		f.full++
		return mk(200, f.bodies[p]), nil
	})}
}

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newRefreshStore(t *testing.T, up *fakeUpstream, urls string) *store {
	t.Helper()
	return &store{
		cfg:    config{chunkSize: 100, fetchLimit: 1 << 20, sources: parseSources(urls)},
		client: up.client(),
		excl:   emptyExclusions(""),
	}
}

func TestRefreshSkipsWhenUpstreamUnchanged(t *testing.T) {
	up := newFakeUpstream(map[string]string{"/a.txt": "a.example.com\nb.example.com\n", "/b.txt": "1.2.3.4\n"})
	st := newRefreshStore(t, up, "threat:http://u/a.txt,http://u/b.txt")
	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first := st.cur.Load()
	if first.dnsCount != 2 || first.ipv4Count != 1 || first.sourcesOK != 2 {
		t.Fatalf("first refresh: dns=%d ipv4=%d ok=%d", first.dnsCount, first.ipv4Count, first.sourcesOK)
	}
	full := up.full

	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st.cur.Load() != first {
		t.Fatal("unchanged upstream should keep the exact same snapshot (no rebuild)")
	}
	if up.full != full || up.cond != 2 {
		t.Fatalf("expected 2 conditional 304s and no new downloads; full=%d->%d cond=%d", full, up.full, up.cond)
	}
}

func TestRefreshRebuildsWhenOneSourceChanges(t *testing.T) {
	up := newFakeUpstream(map[string]string{"/a.txt": "a.example.com\n", "/b.txt": "b.example.com\n"})
	st := newRefreshStore(t, up, "http://u/a.txt,http://u/b.txt")
	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	up.set("/b.txt", "b.example.com\nc.example.com\n")
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap := st.cur.Load()
	if !slices.Equal(snap.dnsServed, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Fatalf("after change: %v (the 304'd source must still contribute)", snap.dnsServed)
	}
}

func TestRefreshPersistentFailureDoesNotForceRebuild(t *testing.T) {
	up := newFakeUpstream(map[string]string{"/a.txt": "a.example.com\n", "/dead.txt": "x.example.com\n"})
	up.fail["/dead.txt"] = true
	st := newRefreshStore(t, up, "http://u/a.txt,http://u/dead.txt")
	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first := st.cur.Load()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st.cur.Load() != first {
		t.Fatal("a source failing the same way as last time must not force a rebuild")
	}
	// Recovery is a change.
	up.fail["/dead.txt"] = false
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := st.cur.Load().dnsCount; got != 2 {
		t.Fatalf("recovered source not merged: dnsCount=%d", got)
	}
}

func TestRefreshExclusionURLChangeRebuildsWithoutRefetch(t *testing.T) {
	up := newFakeUpstream(map[string]string{"/a.txt": "a.example.com\nb.example.com\n", "/ex.txt": "a.example.com\n"})
	st := newRefreshStore(t, up, "http://u/a.txt")
	st.cfg.exclusionURLs = []string{"http://u/ex.txt"}
	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st.cur.Load().dnsCount != 1 {
		t.Fatalf("exclusion not applied: %v", st.cur.Load().dnsServed)
	}
	fullBefore := up.full
	up.set("/ex.txt", "b.example.com\n")
	if err := st.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap := st.cur.Load()
	if !slices.Equal(snap.dnsServed, []string{"a.example.com"}) {
		t.Fatalf("updated exclusion not applied: %v", snap.dnsServed)
	}
	// Only the exclusion list itself was downloaded again, not the blocklist.
	if up.full != fullBefore+1 {
		t.Fatalf("expected 1 new download (exclusion list), got %d", up.full-fullBefore)
	}
}

// --- serving ---

func TestChunkETagStableAndConditional(t *testing.T) {
	st := testStore(t, "")
	rec := doReq(st, "GET", "/lists/ipv4-1.txt", "", "")
	etag := rec.Header().Get("ETag")
	if rec.Code != 200 || etag == "" || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("status=%d etag=%q", rec.Code, etag)
	}
	// Rebuilding with identical content keeps the ETag.
	st.rebuild()
	if got := doReq(st, "GET", "/lists/ipv4-1.txt", "", "").Header().Get("ETag"); got != etag {
		t.Fatalf("etag changed across a no-op rebuild: %q -> %q", etag, got)
	}
	req := httptest.NewRequest("GET", "/lists/ipv4-1.txt", nil)
	req.Header.Set("If-None-Match", etag)
	r2 := httptest.NewRecorder()
	st.routes().ServeHTTP(r2, req)
	if r2.Code != http.StatusNotModified || r2.Body.Len() != 0 {
		t.Fatalf("conditional GET: status=%d body=%q", r2.Code, r2.Body)
	}
	// Changing content changes the ETag.
	if _, err := st.excl.add("9.9.9.9", true); err != nil {
		t.Fatal(err)
	}
	st.rebuild()
	if got := doReq(st, "GET", "/lists/ipv4-1.txt", "", "").Header().Get("ETag"); got == etag {
		t.Fatal("etag did not change after content changed")
	}
}

func TestRefreshEndpointRejectsConcurrentRun(t *testing.T) {
	st := testStore(t, "")
	st.refreshMu.Lock()
	rec := doReq(st, "POST", "/refresh", "", "")
	st.refreshMu.Unlock()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
}

func TestExclusionEditDuringRefreshIsNotBlocked(t *testing.T) {
	st := testStore(t, "secret")
	st.refreshMu.Lock() // a refresh is "running"
	defer st.refreshMu.Unlock()
	done := make(chan int, 1)
	go func() { done <- doReq(st, "POST", "/exclusions", `{"entry":"example.com"}`, "Bearer secret").Code }()
	select {
	case code := <-done:
		if code != http.StatusCreated {
			t.Fatalf("status %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exclusion edit blocked behind a running refresh")
	}
}
