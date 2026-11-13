package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// normalizeEntry converts a raw blocklist token into its canonical form.
// It returns the normalized entry, whether it is an IP/CIDR (vs a DNS name),
// and whether the token was a usable entry at all. AdGuard allow rules (@@)
// are not entries here; see normalizeRule.
func normalizeEntry(raw string) (string, bool, bool) {
	entry, isIP, allow, ok := normalizeRule(raw)
	if allow {
		return "", false, false
	}
	return entry, isIP, ok
}

// normalizeRule is normalizeEntry that also understands AdGuard syntax:
// "@@" marks an allow rule (allow=true), "||" / "|" / "^" / "|...|" wrappers
// are stripped, and "$important" is accepted as a plain block. Any other "$"
// modifier ($third-party, $dnsrewrite, $client=...) makes the rule conditional
// or a rewrite, so it is dropped.
func normalizeRule(raw string) (entry string, isIP, allow, ok bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(s, "@@") {
		allow = true
		s = s[2:]
	}
	if i := strings.IndexByte(s, '$'); i >= 0 {
		for _, m := range strings.Split(s[i+1:], ",") {
			if strings.TrimSpace(m) != "important" {
				return "", false, false, false
			}
		}
		s = s[:i]
	}
	switch {
	case strings.HasPrefix(s, "||"):
		s = s[2:]
	case strings.HasPrefix(s, "|"):
		s = s[1:]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "|"), "^")
	if s == "" {
		return "", false, false, false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Hosts-file lines ("0.0.0.0 example.com") and trailing comments both
	// reduce to a single token: the second field when the first is an IP,
	// otherwise the first field.
	first, second, n := firstTwoFields(s)
	switch {
	case n >= 2:
		if _, err := netip.ParseAddr(first); err == nil {
			s = second
		} else {
			s = first
		}
	case n == 1:
		s = first
	default:
		return "", false, false, false
	}
	s = strings.TrimPrefix(s, "*.")
	if p, err := netip.ParsePrefix(s); err == nil {
		return canonicalPrefix(p), true, allow, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), true, allow, true
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if !validDomain(s) {
		return "", false, false, false
	}
	return s, false, allow, true
}

// canonicalPrefix gives one spelling per network: host bits masked, IPv4-mapped
// IPv6 unmapped to IPv4, and a full-length prefix (/32, /128) written as the
// bare address, so 1.2.3.4, 1.2.3.4/32 and ::ffff:1.2.3.4 deduplicate.
func canonicalPrefix(p netip.Prefix) string {
	p = p.Masked()
	a, bits := p.Addr(), p.Bits()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	if bits == a.BitLen() {
		return a.String()
	}
	return netip.PrefixFrom(a, bits).String()
}

// isCosmetic reports whether line is an AdGuard/uBlock cosmetic, scriptlet or
// HTML-filtering rule such as "example.com##.ad". Those apply to page content,
// not DNS, and must not turn "example.com" into a block entry.
func isCosmetic(line string) bool {
	for i := 1; i < len(line); i++ {
		if line[i] != '#' || line[i-1] == ' ' || line[i-1] == '\t' {
			continue
		}
		r := line[i:]
		for _, m := range []string{"##", "#@#", "#?#", "#$#", "#%#", "#@$#", "#@%#", "#@?#"} {
			if strings.HasPrefix(r, m) {
				return true
			}
		}
	}
	return false
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for rest, last := s, false; !last; {
		l := rest
		if i := strings.IndexByte(rest, '.'); i >= 0 {
			l, rest = rest[:i], rest[i+1:]
		} else {
			last = true
		}
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		hasLetter := false
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z':
				hasLetter = true
			case c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
		if last && !hasLetter { // TLD must contain a letter (rejects bare IPs)
			return false
		}
	}
	return true
}

// firstTwoFields returns the first two whitespace-separated fields of s and
// how many fields it has (capped at 2), without allocating for ASCII input.
func firstTwoFields(s string) (first, second string, n int) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 { // non-ASCII whitespace rules: defer to the stdlib
			f := strings.Fields(s)
			switch len(f) {
			case 0:
				return "", "", 0
			case 1:
				return f[0], "", 1
			}
			return f[0], f[1], 2
		}
	}
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' }
	i := 0
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	start := i
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	if start == i {
		return "", "", 0
	}
	first = s[start:i]
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	start = i
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	if start == i {
		return first, "", 1
	}
	return first, s[start:i], 2
}

// collectStrings flattens every string found in a decoded JSON/YAML/TOML
// document (arrays, nested objects, scalars) into out.
func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[any]any:
		for _, e := range t {
			collectStrings(e, out)
		}
	}
}

func detectFormat(rawURL, contentType string, body []byte) string {
	switch strings.ToLower(path.Ext(strings.Split(rawURL, "?")[0])) {
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".txt", ".list", ".hosts":
		return "txt"
	case ".csv":
		return "csv"
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "yaml"):
		return "yaml"
	case strings.Contains(ct, "toml"):
		return "toml"
	case strings.Contains(ct, "csv"):
		return "csv"
	}
	trimmed := strings.TrimSpace(string(body))
	switch {
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return "json"
	case strings.HasPrefix(trimmed, "- "):
		return "yaml"
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First meaningful line of `key = value` shape suggests TOML.
		if strings.Contains(line, " =") || strings.Contains(line, "= ") {
			return "toml"
		}
		break
	}
	return "txt"
}

// classifier accumulates normalized entries split into domains and IPs.
// Entries written as AdGuard allow rules (@@) are kept apart in aDNS/aIPs; the
// caller decides whether the context (exclusion list or allowlist) honours them.
type classifier struct{ dns, ips, aDNS, aIPs []string }

// all returns block and allow entries together, for contexts where every
// entry is an allowed one (exclusion lists, allowlists).
func (c *classifier) all() (dns, ips []string) {
	return append(c.dns[:len(c.dns):len(c.dns)], c.aDNS...), append(c.ips[:len(c.ips):len(c.ips)], c.aIPs...)
}

// add normalizes one raw token. Surviving entries are cloned so they never
// pin the (much larger) download buffer they were sliced from.
func (c *classifier) add(raw string) {
	entry, isIP, allow, ok := normalizeRule(raw)
	if !ok {
		return
	}
	entry = strings.Clone(entry)
	switch {
	case isIP && allow:
		c.aIPs = append(c.aIPs, entry)
	case isIP:
		c.ips = append(c.ips, entry)
	case allow:
		c.aDNS = append(c.aDNS, entry)
	default:
		c.dns = append(c.dns, entry)
	}
}

// text parses a plain/hosts/adblock body in a single pass, one logical line
// at a time, with no intermediate slice of lines or tokens. Line comments
// (#, //, --, ;) are stripped per line, so CIDRs like 10.0.0.0/8 stay intact
// while "10.0.0.0 // note" is trimmed. Also used for inline custom-list
// textareas.
func (c *classifier) text(body string) {
	for len(body) > 0 {
		var line string
		line, body, _ = strings.Cut(body, "\n")
		if isCosmetic(line) {
			continue
		}
		line = strings.TrimSpace(stripLineComment(line))
		if line == "" || line[0] == '!' || line[0] == '[' {
			continue
		}
		c.add(line)
	}
}

// csvCells streams a CSV document and feeds every non-empty cell to the
// classifier as a candidate entry (header cells that are not domains/IPs are
// dropped by normalizeEntry). It reports false if the CSV reader rejects the
// body, so the caller can fall back to line-oriented parsing.
func (c *classifier) csvCells(body []byte) bool {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.ReuseRecord = true
	for {
		row, err := r.Read()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		for _, cell := range row {
			c.add(cell)
		}
	}
}

// parseList extracts the normalized block entries from one fetched list.
// AdGuard allow rules are ignored; use parseClassified to get them.
func parseList(rawURL, contentType string, body []byte) (dns, ips []string, err error) {
	c, err := parseClassified(rawURL, contentType, body)
	return c.dns, c.ips, err
}

// parseClassified parses one list into block and allow entries.
func parseClassified(rawURL, contentType string, body []byte) (c classifier, err error) {
	switch format := detectFormat(rawURL, contentType, body); format {
	case "json", "yaml", "toml":
		// Structured formats may carry comments; drop them before decoding.
		body = stripComments(body)
		var raw []string
		switch format {
		case "json":
			var v any
			if err := json.Unmarshal(body, &v); err != nil {
				return c, fmt.Errorf("json: %w", err)
			}
			collectStrings(v, &raw)
		case "yaml":
			var v any
			if err := yaml.Unmarshal(body, &v); err != nil {
				return c, fmt.Errorf("yaml: %w", err)
			}
			collectStrings(v, &raw)
		case "toml":
			var v map[string]any
			if err := toml.Unmarshal(body, &v); err != nil {
				return c, fmt.Errorf("toml: %w", err)
			}
			collectStrings(v, &raw)
		}
		for _, r := range raw {
			c.add(r)
		}
	case "csv":
		body = stripComments(body)
		if !c.csvCells(body) {
			c = classifier{}
			c.text(string(body))
		}
	default: // txt: comment stripping happens per line inside text()
		c.text(string(body))
	}
	return c, nil
}
