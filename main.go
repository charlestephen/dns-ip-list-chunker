package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	port                  string
	chunkSize             int
	sources               []sourceRef
	exclusionURLs         []string
	listsFile             string
	refresh               time.Duration
	baseURL               string
	fetchLimit            int64
	adminToken            string
	exclusionsFile        string
	allowlistAlsoExcludes bool
}

func splitURLs(raw string) []string {
	var out []string
	for _, u := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	}) {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func loadConfig() (config, error) {
	cfg := config{
		port:           envOr("PORT", "8080"),
		chunkSize:      100000,
		refresh:        6 * time.Hour,
		baseURL:        strings.TrimSuffix(os.Getenv("BASE_URL"), "/"),
		fetchLimit:     128 << 20,
		adminToken:     os.Getenv("ADMIN_TOKEN"),
		exclusionsFile: envOr("EXCLUSIONS_FILE", "exclusions.json"),
		listsFile:      os.Getenv("LISTS_FILE"),
	}
	if v := os.Getenv("CHUNK_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cfg, fmt.Errorf("CHUNK_SIZE must be a positive integer, got %q", v)
		}
		cfg.chunkSize = n
	}
	if v := os.Getenv("REFRESH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return cfg, fmt.Errorf("REFRESH_INTERVAL must be a duration >= 0, got %q", v)
		}
		cfg.refresh = d
	}
	cfg.sources = parseSources(os.Getenv("BLOCKLIST_URLS"))
	cfg.exclusionURLs = splitURLs(os.Getenv("EXCLUSIONS_URLS"))
	cfg.allowlistAlsoExcludes = envBool("ALLOWLIST_ALSO_EXCLUDES", false)
	if len(cfg.sources) == 0 && cfg.listsFile == "" {
		return cfg, fmt.Errorf("BLOCKLIST_URLS and/or LISTS_FILE is required")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool parses common truthy/falsey strings; empty uses def.
func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

// withholdExclusionListFromBlocks reports whether an exclusion_lists entry
// should be stripped from exported block feeds. Pure exclusion lists always
// withhold. Lists with output_allowlist only withhold when
// ALLOWLIST_ALSO_EXCLUDES is on (so allow feeds can be applied to some
// clients without removing those entries from the global blocklist).
func withholdExclusionListFromBlocks(outputAllowlist, allowlistAlsoExcludes bool) bool {
	if !outputAllowlist {
		return true
	}
	return allowlistAlsoExcludes
}

// categorySnap holds one category's full/served/chunked entry sets.
// An entry belongs to exactly one category (first source wins); the
// global snapshot fields are the union across every category.
type categorySnap struct {
	dnsAll     []string
	ipv4All    []string
	ipv6All    []string
	dnsServed  []string
	ipv4Served []string
	ipv6Served []string
	dnsChunks  [][]string
	ipv4Chunks [][]string
	ipv6Chunks [][]string
	dnsCount   int
	ipv4Count  int
	ipv6Count  int
}

type snapshot struct {
	// *All are the full sorted upstream entries; *Served are the same
	// minus persistent exclusions. Chunks serve the latter so an
	// exclusion can be applied or undone by re-chunking without a refetch.
	// IPs are split by address family — Many controllers expect IPv4 and IPv6 lists
	// separately from domain lists.
	dnsAll     []string
	ipv4All    []string
	ipv6All    []string
	dnsServed  []string
	ipv4Served []string
	ipv6Served []string
	dnsChunks  [][]string
	ipv4Chunks [][]string
	ipv6Chunks [][]string
	dnsCount   int
	ipv4Count  int
	ipv6Count  int
	excluded   int // entries currently withheld by exclusions
	sourcesOK  int
	updatedAt  time.Time // last upstream refresh
	builtAt    time.Time // when these chunks were built (ETag source)
	// categories is keyed by normalized slug; categoryOrder is first-seen
	// order from BLOCKLIST_URLS / custom blocklists (stable index /stats).
	categories    map[string]*categorySnap
	categoryOrder []string
	// allowlists are optional published exclusion-list feeds (subscribe as
	// allowlists on a DNS server / router). Not filtered by exclusions.
	allowlists     map[string]*categorySnap
	allowlistOrder []string
	// allowlistAll is every published allowlist merged, deduplicated and
	// sorted; nil when no allowlist has entries. allowSrc is the LISTS_FILE
	// part of allowlists as supplied to buildSnapshot, kept so an exclusion
	// edit can rebuild without refetching.
	allowlistAll  *categorySnap
	allowSrc      map[string]*categorySnap
	allowSrcOrder []string
}

type store struct {
	cfg    config
	client *http.Client
	excl   *exclusionStore
	// urlDNS/urlIPs are rebuilt from EXCLUSIONS_URLS on each successful
	// exclusion-list fetch. listDNS/listIPs come from LISTS_FILE
	// exclusion_lists. Effective exclusions = persistent ∪ URL ∪ list.
	urlExclMu sync.RWMutex
	urlDNS    map[string]struct{}
	urlIPs    map[string]struct{}
	listDNS   map[string]struct{}
	listIPs   map[string]struct{}
	cur       atomic.Pointer[snapshot]
	// mu guards building and publishing a snapshot (exclusion-driven
	// rebuilds and the final step of a refresh). It is never held across
	// network I/O, so /manage edits stay responsive during a refresh.
	mu sync.Mutex
	// refreshMu serializes whole refreshes and guards the fields below.
	refreshMu sync.Mutex
	// validators holds the ETag / Last-Modified of each source as last
	// loaded into the published snapshot; failed marks sources that errored
	// on the previous attempt; listsSig is the serialized LISTS_FILE that
	// snapshot was built from.
	validators map[string]validator
	failed     map[string]bool
	listsSig   string
	// listURLCache holds the last good copy of each exclusion_lists url, so
	// a failed fetch keeps the previous entries.
	listURLCache map[string]urlEntries
}

type urlEntries struct{ dns, ips []string }

// validator is the HTTP cache validators a source returned.
type validator struct{ etag, lastModified string }

func (v validator) empty() bool { return v.etag == "" && v.lastModified == "" }

// effectiveExclusions merges persistent file exclusions with the latest
// URL-seeded set.
func (s *store) effectiveExclusions() (dns, ips map[string]struct{}) {
	if s.excl != nil {
		dns, ips = s.excl.sets()
	} else {
		dns, ips = map[string]struct{}{}, map[string]struct{}{}
	}
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	for k := range s.urlDNS {
		dns[k] = struct{}{}
	}
	for k := range s.urlIPs {
		ips[k] = struct{}{}
	}
	for k := range s.listDNS {
		dns[k] = struct{}{}
	}
	for k := range s.listIPs {
		ips[k] = struct{}{}
	}
	return dns, ips
}

func (s *store) isExcluded(entry string, isIP bool) bool {
	if s.excl != nil && s.excl.contains(entry, isIP) {
		return true
	}
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	if isIP {
		if _, ok := s.urlIPs[entry]; ok {
			return true
		}
		_, ok := s.listIPs[entry]
		return ok
	}
	if _, ok := s.urlDNS[entry]; ok {
		return true
	}
	_, ok := s.listDNS[entry]
	return ok
}

func (s *store) urlExclusionCount() int {
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	return len(s.urlDNS) + len(s.urlIPs)
}

func (s *store) urlExclusionSets() (dns, ips map[string]struct{}) {
	s.urlExclMu.RLock()
	defer s.urlExclMu.RUnlock()
	dns = make(map[string]struct{}, len(s.urlDNS))
	for k := range s.urlDNS {
		dns[k] = struct{}{}
	}
	ips = make(map[string]struct{}, len(s.urlIPs))
	for k := range s.urlIPs {
		ips[k] = struct{}{}
	}
	return dns, ips
}

// isIPv4Entry reports whether a normalized IP/CIDR belongs on the IPv4
// chunk stream. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) count as IPv4.
func isIPv4Entry(entry string) bool {
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Addr().Unmap().Is4()
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap().Is4()
	}
	return false
}

func splitByIPFamily(ips []string) (v4, v6 []string) {
	for _, e := range ips {
		if isIPv4Entry(e) {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	return v4, v6
}

func finishCategory(cat *categorySnap, size int, exclDNS, exclIPs map[string]struct{}) {
	sortDomains(cat.dnsAll)
	sortIPs(cat.ipv4All)
	sortIPs(cat.ipv6All)
	cat.dnsServed, _ = filterExcluded(cat.dnsAll, exclDNS)
	cat.ipv4Served, _ = filterExcluded(cat.ipv4All, exclIPs)
	cat.ipv6Served, _ = filterExcluded(cat.ipv6All, exclIPs)
	cat.dnsChunks = chunkStrings(cat.dnsServed, size)
	cat.ipv4Chunks = chunkStrings(cat.ipv4Served, size)
	cat.ipv6Chunks = chunkStrings(cat.ipv6Served, size)
	cat.dnsCount = len(cat.dnsServed)
	cat.ipv4Count = len(cat.ipv4Served)
	cat.ipv6Count = len(cat.ipv6Served)
}

func finishAllowlist(cat *categorySnap, size int) {
	// Allowlists are published as-is (not filtered by exclusions).
	sortDomains(cat.dnsAll)
	sortIPs(cat.ipv4All)
	sortIPs(cat.ipv6All)
	cat.dnsServed = append([]string(nil), cat.dnsAll...)
	cat.ipv4Served = append([]string(nil), cat.ipv4All...)
	cat.ipv6Served = append([]string(nil), cat.ipv6All...)
	cat.dnsChunks = chunkStrings(cat.dnsServed, size)
	cat.ipv4Chunks = chunkStrings(cat.ipv4Served, size)
	cat.ipv6Chunks = chunkStrings(cat.ipv6Served, size)
	cat.dnsCount = len(cat.dnsServed)
	cat.ipv4Count = len(cat.ipv4Served)
	cat.ipv6Count = len(cat.ipv6Served)
}

// buildSnapshot derives served chunks from the full sorted entries by
// dropping exact-match exclusions. catAll / allowAll are raw membership
// maps (nil allowed for tests).
func (s *store) buildSnapshot(dnsAll, ipv4All, ipv6All []string, catAll map[string]*categorySnap, catOrder []string, allowAll map[string]*categorySnap, allowOrder []string, sourcesOK int, updatedAt time.Time) *snapshot {
	sortDomains(dnsAll)
	sortIPs(ipv4All)
	sortIPs(ipv6All)
	exclDNS, exclIPs := s.effectiveExclusions()
	dnsServed, dnsDropped := filterExcluded(dnsAll, exclDNS)
	ipv4Served, ipv4Dropped := filterExcluded(ipv4All, exclIPs)
	ipv6Served, ipv6Dropped := filterExcluded(ipv6All, exclIPs)
	excluded := dnsDropped + ipv4Dropped + ipv6Dropped

	categories := map[string]*categorySnap{}
	var order []string
	for _, name := range catOrder {
		src, ok := catAll[name]
		if !ok {
			continue
		}
		// The All slices are immutable once built and sorted in place only
		// when unsorted, so a rebuild can share them instead of copying.
		cat := &categorySnap{dnsAll: src.dnsAll, ipv4All: src.ipv4All, ipv6All: src.ipv6All}
		finishCategory(cat, s.cfg.chunkSize, exclDNS, exclIPs)
		if len(cat.dnsAll)+len(cat.ipv4All)+len(cat.ipv6All) == 0 {
			continue
		}
		categories[name] = cat
		order = append(order, name)
	}

	allowlists, aOrder, allowlistAll := s.publishAllowlists(allowAll, allowOrder)

	return &snapshot{
		dnsAll:         dnsAll,
		ipv4All:        ipv4All,
		ipv6All:        ipv6All,
		dnsServed:      dnsServed,
		ipv4Served:     ipv4Served,
		ipv6Served:     ipv6Served,
		dnsChunks:      chunkStrings(dnsServed, s.cfg.chunkSize),
		ipv4Chunks:     chunkStrings(ipv4Served, s.cfg.chunkSize),
		ipv6Chunks:     chunkStrings(ipv6Served, s.cfg.chunkSize),
		dnsCount:       len(dnsServed),
		ipv4Count:      len(ipv4Served),
		ipv6Count:      len(ipv6Served),
		excluded:       excluded,
		sourcesOK:      sourcesOK,
		updatedAt:      updatedAt,
		builtAt:        time.Now(),
		categories:     categories,
		categoryOrder:  order,
		allowlists:     allowlists,
		allowlistOrder: aOrder,
		allowlistAll:   allowlistAll,
		allowSrc:       allowAll,
		allowSrcOrder:  allowOrder,
	}
}

// publishAllowlists builds the published allowlist feeds: the LISTS_FILE
// lists (allowAll), "remote" for EXCLUSIONS_URLS, "manual" for /manage and
// POST /exclusions entries, plus one merged feed across all of them.
func (s *store) publishAllowlists(allowAll map[string]*categorySnap, allowOrder []string) (map[string]*categorySnap, []string, *categorySnap) {
	dnsSets := map[string]map[string]struct{}{}
	ipSets := map[string]map[string]struct{}{}
	var order []string
	add := func(name string, dns, ips []string) {
		if len(dns)+len(ips) == 0 {
			return
		}
		if dnsSets[name] == nil {
			dnsSets[name], ipSets[name] = map[string]struct{}{}, map[string]struct{}{}
			order = append(order, name)
		}
		for _, e := range dns {
			dnsSets[name][e] = struct{}{}
		}
		for _, e := range ips {
			ipSets[name][e] = struct{}{}
		}
	}
	for _, name := range allowOrder {
		if c := allowAll[name]; c != nil {
			add(name, c.dnsAll, append(append([]string(nil), c.ipv4All...), c.ipv6All...))
		}
	}
	keys := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	ud, ui := s.urlExclusionSets()
	add("remote", keys(ud), keys(ui))
	if s.excl != nil {
		md, mi := s.excl.sets()
		add("manual", keys(md), keys(mi))
	}

	feeds := catAllFromSets(order, dnsSets, ipSets)
	merged := map[string]struct{}{}
	mergedIP := map[string]struct{}{}
	var feedOrder []string
	for _, name := range order {
		cat := feeds[name]
		if cat == nil {
			continue
		}
		finishAllowlist(cat, s.cfg.chunkSize)
		feedOrder = append(feedOrder, name)
		for e := range dnsSets[name] {
			merged[e] = struct{}{}
		}
		for e := range ipSets[name] {
			mergedIP[e] = struct{}{}
		}
	}
	var all *categorySnap
	if len(feedOrder) > 0 {
		all = catAllFromSets([]string{"all"}, map[string]map[string]struct{}{"all": merged}, map[string]map[string]struct{}{"all": mergedIP})["all"]
		finishAllowlist(all, s.cfg.chunkSize)
	}
	return feeds, feedOrder, all
}

// rebuild re-derives the served chunks from the current snapshot's full
// entries after an exclusion change. No-op when nothing is loaded yet.
func (s *store) rebuild() {
	s.rebuildWith(nil, nil, false)
}

// rebuildWith re-derives the snapshot; when replaceAllow is set the LISTS_FILE
// allowlists are replaced by allowAll/allowOrder, otherwise the current ones
// are kept.
func (s *store) rebuildWith(allowAll map[string]*categorySnap, allowOrder []string, replaceAllow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.cur.Load()
	if snap == nil {
		return
	}
	if !replaceAllow {
		allowAll, allowOrder = snap.allowSrc, snap.allowSrcOrder
	}
	s.cur.Store(s.buildSnapshot(snap.dnsAll, snap.ipv4All, snap.ipv6All, snap.categories, snap.categoryOrder, allowAll, allowOrder, snap.sourcesOK, snap.updatedAt))
}

func chunkStrings(entries []string, size int) [][]string {
	var chunks [][]string
	for start := 0; start < len(entries); start += size {
		chunks = append(chunks, entries[start:min(start+size, len(entries))])
	}
	return chunks
}

// fetched is the result of one source download.
type fetched struct {
	dns, ips    []string
	adns, aips  []string // AdGuard allow rules (@@)
	v           validator
	notModified bool
}

// fetch downloads and parses one list. When prev is non-nil its validators
// are sent as If-None-Match / If-Modified-Since and a 304 yields
// notModified without a body.
func (s *store) fetch(ctx context.Context, url string, prev *validator) (fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetched{}, err
	}
	req.Header.Set("User-Agent", "dns-ip-list-chunker/1.6")
	if prev != nil {
		if prev.etag != "" {
			req.Header.Set("If-None-Match", prev.etag)
		}
		if prev.lastModified != "" {
			req.Header.Set("If-Modified-Since", prev.lastModified)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fetched{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && prev != nil {
		return fetched{notModified: true, v: *prev}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return fetched{}, fmt.Errorf("HTTP %s", resp.Status)
	}
	var buf bytes.Buffer
	if n := resp.ContentLength; n > 0 && n <= s.cfg.fetchLimit {
		buf.Grow(int(n)) // exact size: avoids ReadAll's repeated grow-and-copy
	}
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, s.cfg.fetchLimit)); err != nil {
		return fetched{}, err
	}
	c, err := parseClassified(url, resp.Header.Get("Content-Type"), buf.Bytes())
	if err != nil {
		return fetched{}, err
	}
	return fetched{dns: c.dns, ips: c.ips, adns: c.aDNS, aips: c.aIPs, v: validator{resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")}}, nil
}

// fetchOne downloads a list used as an exclusion or allowlist, where every
// entry (including AdGuard @@ rules) is an allowed one.
func (s *store) fetchOne(ctx context.Context, url string) (dns, ips []string, err error) {
	f, err := s.fetch(ctx, url, nil)
	return append(f.dns, f.adns...), append(f.ips, f.aips...), err
}

func toSet(entries []string) map[string]struct{} {
	m := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		m[e] = struct{}{}
	}
	return m
}

// fetchListURL fetches one exclusion_lists url. A failure keeps the last good
// copy. It reports whether the entries differ from the previous copy.
func (s *store) fetchListURL(ctx context.Context, url string) (dns, ips []string, changed bool) {
	fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	d, i, err := s.fetchOne(fetchCtx, url)
	prev, had := s.listURLCache[url]
	if err != nil {
		log.Printf("allowlist source failed (keeping previous copy): %s: %v", url, err)
		return prev.dns, prev.ips, false
	}
	if s.listURLCache == nil {
		s.listURLCache = map[string]urlEntries{}
	}
	s.listURLCache[url] = urlEntries{d, i}
	return d, i, !had || !sameSet(toSet(d), toSet(prev.dns)) || !sameSet(toSet(i), toSet(prev.ips))
}

func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// refreshExclusionURLs fetches EXCLUSIONS_URLS and replaces the in-memory
// URL-sourced exclusion sets when at least one URL succeeds. Total failure
// keeps the previous URL-sourced set. No URLs configured clears them. It
// reports whether the effective set changed.
func (s *store) refreshExclusionURLs(ctx context.Context) (changed bool) {
	if len(s.cfg.exclusionURLs) == 0 {
		s.urlExclMu.Lock()
		changed = len(s.urlDNS)+len(s.urlIPs) > 0
		s.urlDNS, s.urlIPs = nil, nil
		s.urlExclMu.Unlock()
		return changed
	}
	dnsSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})
	ok := 0
	var failures []string
	for _, url := range s.cfg.exclusionURLs {
		fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		dns, ips, err := s.fetchOne(fetchCtx, url)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		ok++
		for _, e := range dns {
			dnsSet[e] = struct{}{}
		}
		for _, e := range ips {
			ipSet[e] = struct{}{}
		}
	}
	for _, f := range failures {
		log.Printf("exclusion source failed (others still applied): %s", f)
	}
	if ok == 0 {
		log.Printf("exclusion sources: all %d failed; keeping previous URL exclusions", len(s.cfg.exclusionURLs))
		return false
	}
	s.urlExclMu.Lock()
	changed = !sameSet(s.urlDNS, dnsSet) || !sameSet(s.urlIPs, ipSet)
	s.urlDNS, s.urlIPs = dnsSet, ipSet
	s.urlExclMu.Unlock()
	log.Printf("exclusion sources: loaded %d DNS + %d IP from %d/%d URL(s)",
		len(dnsSet), len(ipSet), ok, len(s.cfg.exclusionURLs))
	return changed
}

// catAllFromSets builds per-category entry slices from membership sets. Only
// the (small) allowlists use it; block categories come out of mergeSources
// already sorted.
func catAllFromSets(catOrder []string, catDNS, catIP map[string]map[string]struct{}) map[string]*categorySnap {
	catAll := make(map[string]*categorySnap, len(catOrder))
	for _, name := range catOrder {
		dnsSet := catDNS[name]
		ipSet := catIP[name]
		if len(dnsSet)+len(ipSet) == 0 {
			continue
		}
		cat := &categorySnap{}
		for e := range dnsSet {
			cat.dnsAll = append(cat.dnsAll, e)
		}
		var catIPs []string
		for e := range ipSet {
			catIPs = append(catIPs, e)
		}
		sortIPs(catIPs)
		cat.ipv4All, cat.ipv6All = splitByIPFamily(catIPs)
		catAll[name] = cat
	}
	return catAll
}

// sourceEntries is one parsed source: its category slot (index into the
// first-seen category order) and its entries. Position in the slice is the
// source's priority; the earliest source containing an entry owns it.
type sourceEntries struct {
	cat      int
	dns, ips []string
}

// mergeSources deduplicates every source into globally sorted domain / IPv4 /
// IPv6 slices and splits them into per-category slices (first source wins),
// with a single sort per stream and no per-entry maps. Walking the sorted
// result in order keeps every category slice sorted for free.
func mergeSources(srcs []sourceEntries, catOrder []string) (dns, ipv4, ipv6 []string, cats map[string]*categorySnap) {
	cats = make(map[string]*categorySnap, len(catOrder))
	catSnaps := make([]*categorySnap, len(catOrder))
	for i, name := range catOrder {
		catSnaps[i] = &categorySnap{}
		cats[name] = catSnaps[i]
	}

	type domainEnt struct {
		key, val string
		src      int32
	}
	nd, ni := 0, 0
	for _, src := range srcs {
		nd += len(src.dns)
		ni += len(src.ips)
	}
	ds := make([]domainEnt, 0, nd)
	for i, src := range srcs {
		for _, e := range src.dns {
			ds = append(ds, domainEnt{domainKey(e), e, int32(i)})
		}
		srcs[i].dns = nil // release as we go
	}
	slices.SortFunc(ds, func(a, b domainEnt) int {
		return cmp.Or(strings.Compare(a.key, b.key), cmp.Compare(a.src, b.src))
	})
	dns = make([]string, 0, len(ds))
	for i, d := range ds {
		if i > 0 && d.key == ds[i-1].key {
			continue // duplicate of a higher-priority source
		}
		dns = append(dns, d.val)
		c := catSnaps[srcs[d.src].cat]
		c.dnsAll = append(c.dnsAll, d.val)
	}
	ds = nil

	type ipEnt struct {
		addr netip.Addr
		bits int
		val  string
		src  int32
	}
	is := make([]ipEnt, 0, ni)
	for i, src := range srcs {
		for _, e := range src.ips {
			a, b := ipSortKey(e)
			is = append(is, ipEnt{a, b, e, int32(i)})
		}
		srcs[i].ips = nil
	}
	slices.SortFunc(is, func(a, b ipEnt) int {
		return cmp.Or(compareIPKeys(a.val, a.addr, a.bits, b.val, b.addr, b.bits), strings.Compare(a.val, b.val), cmp.Compare(a.src, b.src))
	})
	for i, e := range is {
		if i > 0 && e.val == is[i-1].val {
			continue
		}
		c := catSnaps[srcs[e.src].cat]
		if e.addr.Is4() {
			ipv4 = append(ipv4, e.val)
			c.ipv4All = append(c.ipv4All, e.val)
		} else {
			ipv6 = append(ipv6, e.val)
			c.ipv6All = append(c.ipv6All, e.val)
		}
	}
	return dns, ipv4, ipv6, cats
}

// refresh fetches every source, merges custom/exclusion lists from LISTS_FILE,
// deduplicates, and atomically swaps in the new chunked snapshot.
func (s *store) refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.refreshLocked(ctx)
}

// refreshLocked does the work of refresh; the caller holds refreshMu. The
// expensive steps (network, parsing, sorting) run without s.mu so exclusion
// edits stay responsive; only the final build-and-publish takes it.
func (s *store) refreshLocked(ctx context.Context) error {
	exclChanged := s.refreshExclusionURLs(ctx)

	lists, err := loadListsFile(s.cfg.listsFile)
	if err != nil {
		log.Printf("lists file %s: %v (continuing without it)", s.cfg.listsFile, err)
		lists = listsFile{}
	}
	sigBytes, _ := json.Marshal(lists)
	listsSig := string(sigBytes)

	listDNS := make(map[string]struct{})
	listIPs := make(map[string]struct{})
	allowDNS := make(map[string]map[string]struct{})
	allowIP := make(map[string]map[string]struct{})
	var allowOrder []string
	seenAllow := make(map[string]bool)
	listURLChanged := false
	for _, excl := range lists.ExclusionLists {
		dns, ips := excl.parsedAllowEntries()
		if excl.URL != "" {
			ud, ui, ch := s.fetchListURL(ctx, excl.URL)
			dns, ips = append(dns, ud...), append(ips, ui...)
			listURLChanged = listURLChanged || ch
		}
		if withholdExclusionListFromBlocks(excl.OutputAllowlist, s.cfg.allowlistAlsoExcludes) {
			for _, e := range dns {
				listDNS[e] = struct{}{}
			}
			for _, e := range ips {
				listIPs[e] = struct{}{}
			}
		}
		if !excl.OutputAllowlist {
			continue
		}
		cat := excl.categorySlug()
		if !seenAllow[cat] {
			seenAllow[cat] = true
			allowOrder = append(allowOrder, cat)
		}
		if allowDNS[cat] == nil {
			allowDNS[cat] = make(map[string]struct{})
			allowIP[cat] = make(map[string]struct{})
		}
		for _, e := range dns {
			allowDNS[cat][e] = struct{}{}
		}
		for _, e := range ips {
			allowIP[cat][e] = struct{}{}
		}
	}
	s.urlExclMu.Lock()
	s.listDNS, s.listIPs = listDNS, listIPs
	s.urlExclMu.Unlock()

	// Pass 1: conditional fetch. A source answering 304 is not parsed.
	havePrev := s.cur.Load() != nil
	results := make([]fetched, len(s.cfg.sources))
	errs := make([]error, len(s.cfg.sources))
	allUnchanged := havePrev && listsSig == s.listsSig
	for i, src := range s.cfg.sources {
		var prev *validator
		if v, ok := s.validators[src.URL]; ok && havePrev && !v.empty() {
			prev = &v
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		results[i], errs[i] = s.fetch(fetchCtx, src.URL, prev)
		cancel()
		switch {
		case errs[i] != nil:
			// Failing again exactly as it did last time leaves the snapshot valid.
			if !s.failed[src.URL] {
				allUnchanged = false
			}
		case !results[i].notModified:
			allUnchanged = false
		}
	}
	if allUnchanged {
		if exclChanged || listURLChanged {
			// only an exclusion or allowlist moved: re-filter, no re-sort
			s.rebuildWith(catAllFromSets(allowOrder, allowDNS, allowIP), allowOrder, true)
			log.Printf("refresh: sources unchanged; re-applied updated exclusion lists")
		} else {
			log.Printf("refresh: no upstream changes (%d source(s) unchanged); keeping current lists", len(s.cfg.sources))
		}
		return nil
	}

	// Pass 2: something changed, so the whole set must be rebuilt. Sources
	// that answered 304 have no data in hand; fetch them in full.
	var srcs []sourceEntries
	var catOrder []string
	catIdx := make(map[string]int)
	slot := func(category string) int {
		i, ok := catIdx[category]
		if !ok {
			i = len(catOrder)
			catIdx[category] = i
			catOrder = append(catOrder, category)
		}
		return i
	}
	validators := make(map[string]validator)
	failed := make(map[string]bool)
	okCount := 0
	var failures []string
	for i, src := range s.cfg.sources {
		res, err := results[i], errs[i]
		if err == nil && res.notModified {
			fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			res, err = s.fetch(fetchCtx, src.URL, nil)
			cancel()
		}
		if err != nil {
			failed[src.URL] = true
			failures = append(failures, fmt.Sprintf("%s (%s): %v", src.URL, src.Category, err))
			continue
		}
		okCount++
		if !res.v.empty() {
			validators[src.URL] = res.v
		}
		srcs = append(srcs, sourceEntries{cat: slot(src.Category), dns: res.dns, ips: res.ips})
		results[i] = fetched{} // drop our reference; mergeSources releases the rest
	}
	for _, custom := range lists.CustomBlocklists {
		dns, ips := custom.parsedEntries()
		if len(dns)+len(ips) == 0 {
			continue
		}
		okCount++
		srcs = append(srcs, sourceEntries{cat: slot(custom.categorySlug()), dns: dns, ips: ips})
	}
	dns, ipv4, ipv6, catAll := mergeSources(srcs, catOrder)
	if len(dns)+len(ipv4)+len(ipv6) == 0 {
		if havePrev {
			return fmt.Errorf("refresh produced no entries (keeping previous lists); failures: %s", strings.Join(failures, "; "))
		}
		return fmt.Errorf("refresh produced no entries; failures: %s", strings.Join(failures, "; "))
	}
	allowAll := catAllFromSets(allowOrder, allowDNS, allowIP)

	s.mu.Lock()
	snap := s.buildSnapshot(dns, ipv4, ipv6, catAll, catOrder, allowAll, allowOrder, okCount, time.Now())
	s.cur.Store(snap)
	s.mu.Unlock()
	s.validators, s.failed, s.listsSig = validators, failed, listsSig

	for _, f := range failures {
		log.Printf("source failed (others still applied): %s", f)
	}
	log.Printf("refreshed: %d DNS + %d IPv4 + %d IPv6 unique entries from %d source(s) (%d block categor(ies), %d allowlist(s)) -> %d/%d/%d chunk(s) of <= %d (%d withheld)",
		len(dns), len(ipv4), len(ipv6), okCount, len(snap.categories), len(snap.allowlists),
		len(snap.dnsChunks), len(snap.ipv4Chunks), len(snap.ipv6Chunks), s.cfg.chunkSize, snap.excluded)
	// The transient parse/sort buffers dwarf the published snapshot; hand
	// them back to the OS instead of leaving them as idle RSS.
	debug.FreeOSMemory()
	return nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	excl, err := loadExclusions(cfg.exclusionsFile)
	if err != nil {
		log.Printf("exclusions: %v (starting with none; file will be rewritten on first change)", err)
		excl = emptyExclusions(cfg.exclusionsFile)
	} else if n := excl.count(); n > 0 {
		log.Printf("exclusions: loaded %d from %s", n, cfg.exclusionsFile)
	}
	st := &store{cfg: cfg, client: &http.Client{}, excl: excl}
	if n := len(cfg.exclusionURLs); n > 0 {
		log.Printf("exclusions: %d URL source(s) configured (fetched on each refresh)", n)
	}

	ctx := context.Background()
	if err := st.refresh(ctx); err != nil {
		log.Printf("initial refresh: %v", err)
	}
	if cfg.refresh > 0 {
		go func() {
			t := time.NewTicker(cfg.refresh)
			defer t.Stop()
			for range t.C {
				if err := st.refresh(ctx); err != nil {
					log.Printf("scheduled refresh: %v", err)
				}
			}
		}()
	}

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           st.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on :%s (chunk size %d, %d source(s), refresh %s)", cfg.port, cfg.chunkSize, len(cfg.sources), cfg.refresh)
	log.Fatal(srv.ListenAndServe())
}
