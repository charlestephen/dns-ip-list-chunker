# Changelog

## 1.4.0

- **`ALLOWLIST_ALSO_EXCLUDES`** (default `false`): when enabled, entries from
  `exclusion_lists` with `output_allowlist: true` are also withheld from
  exported block feeds. Default leaves allowlisted entries in the blocklist so
  allow feeds can be applied only to some clients. Pure exclusion lists
  (`output_allowlist` unset/`false`), `EXCLUSIONS_URLS`, and `/manage`
  exclusions still always withhold.
- `/stats` includes `allowlist_also_excludes`.

## 1.3.0

- **Fix:** `//` and `--` comment markers only apply at line start or after
  whitespace, so domains like `o--o.duckdns.org` and `xn--…` punycode labels
  are no longer truncated or dropped.
- **CSV** list ingestion (`.csv` / `text/csv`); every cell is a candidate entry.
- **`LISTS_FILE`** (YAML or JSON): `custom_blocklists` (inline named/categorized
  block entries) and `exclusion_lists` (inline allow/exclude entries with
  optional `output_allowlist: true` → `/allowlists/<category>/…` feeds).
- Block sources may be URL-only, inline-only, or both (`BLOCKLIST_URLS` and/or
  `LISTS_FILE`).
- Project renamed to **dns-ip-list-chunker** (generic DNS/router blocklist and
  allowlist chunking; not UniFi-specific).

## 1.2.0

- **Source categories:** tag each `BLOCKLIST_URLS` entry as
  `category:https://…` (kebab-cased, lowercased). Untagged sources use
  `default`.
- **Dual feeds:** keep the global `/lists/{dns,ipv4,ipv6}-N.txt` “all” feed
  and add per-category URLs at `/lists/<category>/{dns,ipv4,ipv6}-N.txt`.
- Cross-category duplicates are assigned to **one** category (first source
  wins) and still appear once in the all feed.
- Index (`/`) and `/stats` list category chunk URLs; `/search` returns
  `category` when known.
- **Comment stripping** for txt / JSON / YAML / TOML: drop `#`, `//`, `--`,
  and `;` through end-of-line (quote-aware). CIDRs like `10.0.0.0/8` stay
  intact; `10.0.0.0 // note` is trimmed.

## 1.1.0

- `EXCLUSIONS_URLS`: remote exclusion lists re-fetched on every refresh and
  unioned with the persistent exclusions file (URL-only removals return 409).

## 1.0.0

- First stable release: domain / IPv4 / IPv6 chunk streams, search + manage
  UI, persistent exclusions, published multi-arch image.
