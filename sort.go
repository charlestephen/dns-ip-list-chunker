package main

import (
	"net/netip"
	"slices"
	"strings"
)

// domainCompare orders domains by label from the root (right) leftward:
// TLD first (com before nyc), then the next label (cloudflare.com before
// google.com), and so on. When one name is a proper suffix of the other
// under that order, the shorter (closer to the root) comes first —
// example.com before mail.example.com.
//
// It walks both names from the right without allocating, because it runs
// inside binary searches and sortedness checks over millions of entries.
func domainCompare(a, b string) int {
	if a == b {
		return 0
	}
	ae, be := len(a), len(b) // exclusive end of the label still to compare; -1 = exhausted
	for {
		switch {
		case ae < 0 && be < 0:
			return 0
		case ae < 0:
			return -1
		case be < 0:
			return 1
		}
		as := strings.LastIndexByte(a[:ae], '.') + 1
		bs := strings.LastIndexByte(b[:be], '.') + 1
		if c := strings.Compare(a[as:ae], b[bs:be]); c != 0 {
			return c
		}
		ae, be = as-1, bs-1
	}
}

func domainLess(a, b string) bool { return domainCompare(a, b) < 0 }

// domainKey rewrites a domain with its labels reversed and joined by NUL,
// so a plain byte comparison of two keys equals domainCompare of the names:
// NUL sorts below every valid label byte, which keeps "a" before "a-b" and
// a parent before its subdomains.
func domainKey(d string) string {
	var b strings.Builder
	b.Grow(len(d))
	end := len(d)
	for end >= 0 {
		start := strings.LastIndexByte(d[:end], '.') + 1
		b.WriteString(d[start:end])
		if start > 0 {
			b.WriteByte(0)
		}
		end = start - 1
	}
	return b.String()
}

// sortDomains sorts in place, root-first. Keys are built once up front
// instead of re-deriving label order inside every comparison, and input
// that is already sorted (the exclusion-rebuild path) returns after one
// linear pass.
func sortDomains(entries []string) {
	if len(entries) < 2 || slices.IsSortedFunc(entries, domainCompare) {
		return
	}
	type keyed struct{ key, val string }
	ks := make([]keyed, len(entries))
	for i, e := range entries {
		ks[i] = keyed{domainKey(e), e}
	}
	slices.SortFunc(ks, func(x, y keyed) int { return strings.Compare(x.key, y.key) })
	for i := range ks {
		entries[i] = ks[i].val
	}
}

// ipSortKey is the numeric sort key for an IP or CIDR. Addresses are
// compared as integers (IPv4 as 32-bit, IPv6 as 128-bit); IPv4-mapped
// IPv6 forms are Unmapped so they order with other IPv4 entries. Prefix
// length is the tie-breaker (hosts use -1 so a bare address sorts before
// the same address written as a /32 or /128).
func ipSortKey(entry string) (netip.Addr, int) {
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Addr().Unmap(), p.Bits()
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return a.Unmap(), -1
	}
	return netip.Addr{}, -1
}

func ipCompare(a, b string) int {
	aa, ab := ipSortKey(a)
	ba, bb := ipSortKey(b)
	return compareIPKeys(a, aa, ab, b, ba, bb)
}

func compareIPKeys(as string, aa netip.Addr, ab int, bs string, ba netip.Addr, bb int) int {
	switch {
	case !aa.IsValid() && !ba.IsValid():
		return strings.Compare(as, bs)
	case !aa.IsValid():
		return 1
	case !ba.IsValid():
		return -1
	}
	if c := aa.Compare(ba); c != 0 {
		return c
	}
	switch {
	case ab < bb:
		return -1
	case ab > bb:
		return 1
	default:
		return 0
	}
}

// sortIPs sorts in place by numeric address. Each entry is parsed once
// (not twice per comparison) and the sort is stable, so equal keys keep
// their input order. Already-sorted input returns after one linear pass.
func sortIPs(entries []string) {
	if len(entries) < 2 || slices.IsSortedFunc(entries, ipCompare) {
		return
	}
	type keyed struct {
		addr netip.Addr
		bits int
		val  string
	}
	ks := make([]keyed, len(entries))
	for i, e := range entries {
		a, b := ipSortKey(e)
		ks[i] = keyed{a, b, e}
	}
	slices.SortStableFunc(ks, func(x, y keyed) int {
		return compareIPKeys(x.val, x.addr, x.bits, y.val, y.addr, y.bits)
	})
	for i := range ks {
		entries[i] = ks[i].val
	}
}
