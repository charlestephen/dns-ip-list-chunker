package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// normalizeEntry converts a raw blocklist token into its canonical form.
// It returns the normalized entry, whether it is an IP/CIDR (vs a DNS name),
// and whether the token was a usable entry at all.
func normalizeEntry(raw string) (string, bool, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || strings.HasPrefix(s, "@@") { // @@ = adblock exception rule
		return "", false, false
	}
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Hosts-file lines ("0.0.0.0 example.com") and trailing comments both
	// reduce to a single token: the second field when the first is an IP,
	// otherwise the first field.
	fields := strings.Fields(s)
	switch {
	case len(fields) >= 2:
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			s = fields[1]
		} else {
			s = fields[0]
		}
	case len(fields) == 1:
		s = fields[0]
	default:
		return "", false, false
	}
	s = strings.TrimPrefix(s, "*.")
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), true, true
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if !validDomain(s) {
		return "", false, false
	}
	return s, false, true
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if len(l) == 0 || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
		if i == len(labels)-1 { // TLD must contain a letter (rejects bare IPs)
			hasLetter := false
			for _, c := range l {
				if c >= 'a' && c <= 'z' {
					hasLetter = true
				}
			}
			if !hasLetter {
				return false
			}
		}
	}
	return true
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

// parseList extracts the normalized, classified entries from one fetched list.
// Line comments (#, //, --, ;) are stripped before format-specific parsing so
// CIDRs like 10.0.0.0/8 stay intact while 10.0.0.0 // note is trimmed.
func parseList(rawURL, contentType string, body []byte) (dns, ips []string, err error) {
	format := detectFormat(rawURL, contentType, body)
	body = stripComments(body)
	var raw []string
	switch format {
	case "json":
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, nil, fmt.Errorf("json: %w", err)
		}
		collectStrings(v, &raw)
	case "yaml":
		var v any
		if err := yaml.Unmarshal(body, &v); err != nil {
			return nil, nil, fmt.Errorf("yaml: %w", err)
		}
		collectStrings(v, &raw)
	case "toml":
		var v map[string]any
		if err := toml.Unmarshal(body, &v); err != nil {
			return nil, nil, fmt.Errorf("toml: %w", err)
		}
		collectStrings(v, &raw)
	case "csv":
		raw = parseCSVEntries(body)
	default: // txt
		raw = parseTextEntries(string(body))
	}
	dns, ips = classifyEntries(raw)
	return dns, ips, nil
}

// parseTextEntries splits a plain/hosts/adblock body into raw tokens (one
// logical line each). Also used for inline custom-list textareas.
func parseTextEntries(body string) []string {
	var raw []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(stripLineComment(line))
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		raw = append(raw, line)
	}
	return raw
}

// parseCSVEntries reads every cell from a CSV document and returns non-empty
// cells as candidate entries (header cells that are not domains/IPs are
// dropped later by normalizeEntry).
func parseCSVEntries(body []byte) []string {
	r := csv.NewReader(strings.NewReader(string(body)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		// Fall back to line-oriented parsing if the CSV reader rejects the body.
		return parseTextEntries(string(body))
	}
	var raw []string
	for _, row := range rows {
		for _, cell := range row {
			cell = strings.TrimSpace(cell)
			if cell == "" {
				continue
			}
			raw = append(raw, cell)
		}
	}
	return raw
}

// classifyEntries normalizes raw tokens into dns / ip slices.
func classifyEntries(raw []string) (dns, ips []string) {
	for _, r := range raw {
		entry, isIP, ok := normalizeEntry(r)
		if !ok {
			continue
		}
		if isIP {
			ips = append(ips, entry)
		} else {
			dns = append(dns, entry)
		}
	}
	return dns, ips
}
