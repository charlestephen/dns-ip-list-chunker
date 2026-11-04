package main

import (
	"strings"
	"unicode"
)

const defaultCategory = "default"

// sourceRef is one BLOCKLIST_URLS entry: an optional category tag plus URL.
// Tagged form: category:https://example.com/list.txt
// Untagged URLs land in "default".
type sourceRef struct {
	Category string
	URL      string
}

// normalizeCategory lowercases and kebab-cases a category for use in paths.
func normalizeCategory(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	lastHyphen := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastHyphen = false
		case r == ' ' || r == '_' || r == '-' || r == '.':
			if b.Len() > 0 && !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return defaultCategory
	}
	return out
}

func isHTTPScheme(s string) bool {
	s = strings.ToLower(s)
	return s == "http" || s == "https"
}

// parseSource splits an optional category tag from a source URL.
// "threat:https://x.test/list.txt" → ("threat", "https://x.test/list.txt")
// "https://x.test/list.txt" → ("default", "https://x.test/list.txt")
func parseSource(raw string) sourceRef {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return sourceRef{Category: defaultCategory}
	}
	i := strings.Index(raw, "://")
	if i <= 0 {
		return sourceRef{Category: defaultCategory, URL: raw}
	}
	before := raw[:i] // "threat:https" or "https"
	j := strings.LastIndex(before, ":")
	if j < 0 {
		return sourceRef{Category: defaultCategory, URL: raw}
	}
	scheme := before[j+1:]
	if !isHTTPScheme(scheme) {
		return sourceRef{Category: defaultCategory, URL: raw}
	}
	cat := normalizeCategory(before[:j])
	return sourceRef{
		Category: cat,
		URL:      scheme + raw[i:],
	}
}

func parseSources(raw string) []sourceRef {
	var out []sourceRef
	for _, u := range splitURLs(raw) {
		src := parseSource(u)
		if src.URL == "" {
			continue
		}
		out = append(out, src)
	}
	return out
}
