# Changelog

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
