package main

import (
	"testing"
	"time"
)

func TestWithholdExclusionListFromBlocks(t *testing.T) {
	cases := []struct {
		name            string
		outputAllowlist bool
		alsoExcludes    bool
		wantWithhold    bool
	}{
		{"pure exclusion", false, false, true},
		{"pure exclusion ignores toggle", false, true, true},
		{"allowlist default keeps in blocks", true, false, false},
		{"allowlist with toggle strips from blocks", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withholdExclusionListFromBlocks(tc.outputAllowlist, tc.alsoExcludes)
			if got != tc.wantWithhold {
				t.Fatalf("got %v, want %v", got, tc.wantWithhold)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("ALLOWLIST_ALSO_EXCLUDES", "")
	if envBool("ALLOWLIST_ALSO_EXCLUDES", false) {
		t.Fatal("empty should use default false")
	}
	t.Setenv("ALLOWLIST_ALSO_EXCLUDES", "true")
	if !envBool("ALLOWLIST_ALSO_EXCLUDES", false) {
		t.Fatal("true should parse")
	}
	t.Setenv("ALLOWLIST_ALSO_EXCLUDES", "0")
	if envBool("ALLOWLIST_ALSO_EXCLUDES", true) {
		t.Fatal("0 should be false")
	}
}

func TestAllowlistAlsoExcludesFiltersBlockSnapshot(t *testing.T) {
	st := &store{
		cfg:     config{chunkSize: 100, allowlistAlsoExcludes: true},
		listDNS: map[string]struct{}{"school.edu": {}},
	}
	dnsAll := []string{"ads.example.com", "school.edu"}
	snap := st.buildSnapshot(dnsAll, nil, nil, nil, nil, nil, nil, 1, time.Now())
	if snap.dnsCount != 1 || snap.dnsServed[0] != "ads.example.com" {
		t.Fatalf("expected school.edu withheld, got %+v", snap.dnsServed)
	}

	st.listDNS = nil // allowlist-only path: refresh does not put these in listDNS
	snap = st.buildSnapshot(dnsAll, nil, nil, nil, nil, nil, nil, 1, time.Now())
	if snap.dnsCount != 2 {
		t.Fatalf("expected both entries served when allowlist does not exclude, got %+v", snap.dnsServed)
	}
}
