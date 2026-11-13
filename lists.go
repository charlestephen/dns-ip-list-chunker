package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// namedList is one inline or file-backed list with a display name, category
// slug, and newline-separated entries (domains / IPs / CIDRs).
type namedList struct {
	Name     string `yaml:"name" json:"name"`
	Category string `yaml:"category" json:"category"`
	Entries  string `yaml:"entries" json:"entries"`
	// URL optionally points at a remote list (any supported format) that is
	// merged with Entries. Used by exclusion_lists.
	URL             string `yaml:"url" json:"url"`
	OutputAllowlist bool   `yaml:"output_allowlist" json:"output_allowlist"`
}

// listsFile is the optional LISTS_FILE document. Custom blocklists merge into
// the same category feeds as BLOCKLIST_URLS. Exclusion lists without
// output_allowlist always withhold matches from block feeds. Lists with
// output_allowlist publish allowlist chunk URLs, and only also withhold from
// block feeds when ALLOWLIST_ALSO_EXCLUDES is enabled.
type listsFile struct {
	CustomBlocklists []namedList `yaml:"custom_blocklists" json:"custom_blocklists"`
	ExclusionLists   []namedList `yaml:"exclusion_lists" json:"exclusion_lists"`
}

func loadListsFile(path string) (listsFile, error) {
	var out listsFile
	if path == "" {
		return out, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return out, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(body, &out); err != nil {
			return out, fmt.Errorf("lists json: %w", err)
		}
		return out, nil
	}
	if err := yaml.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("lists yaml: %w", err)
	}
	return out, nil
}

func (n namedList) categorySlug() string {
	if strings.TrimSpace(n.Category) != "" {
		return normalizeCategory(n.Category)
	}
	if strings.TrimSpace(n.Name) != "" {
		return normalizeCategory(n.Name)
	}
	return defaultCategory
}

// parsedEntries returns the block entries of a custom blocklist. AdGuard
// allow rules (@@) in it are ignored.
func (n namedList) parsedEntries() (dns, ips []string) {
	var c classifier
	c.text(n.Entries)
	return c.dns, c.ips
}

// parsedAllowEntries returns every entry of an exclusion list, including
// AdGuard allow rules (@@), since all of them are allowed entries there.
func (n namedList) parsedAllowEntries() (dns, ips []string) {
	var c classifier
	c.text(n.Entries)
	return c.all()
}
