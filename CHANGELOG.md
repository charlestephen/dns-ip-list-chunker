# Changelog

## 1.6.0

- **AdGuard syntax:** `|http://x|` and `|x^` forms parse; `$important` is a
  plain block; rules with any other modifier are dropped. Cosmetic rules
  (`example.org##.ad`, `#@#`, `#?#`, `#$#`, `#%#`) are ignored; they used to
  turn `example.org` into a block entry. `@@` allow rules are no longer
  discarded: they count in exclusion lists and allowlists and are ignored in
  blocklists.
- **IP deduplication:** `1.2.3.4`, `1.2.3.4/32` and `::ffff:1.2.3.4` are one
  entry (`1.2.3.4`), and IPv4-mapped CIDRs move to the IPv4 stream.
- **Allowlists from a URL:** `exclusion_lists` entries accept `url:` (any
  supported format). A failed fetch keeps the last good copy, and a change to
  only that URL republishes without re-parsing the blocklists.
- **Published exclusions:** `EXCLUSIONS_URLS` entries are served as the
  `remote` allowlist and `/manage` entries as the `manual` allowlist. They are
  still always withheld from block feeds.
- **Merged allowlist:** `/allowlists/dns-<n>.txt`, `ipv4-<n>.txt` and
  `ipv6-<n>.txt` serve every allowlist deduplicated and sorted; `/stats` gains
  `allowlist_all` and `/` lists the feed.

## 1.5.0

Performance release. Output is byte-identical to 1.4.0 for the same inputs
(verified on 26 real-world sources: 1.28M domains and 496k IPs, every chunk
stream and category).

- **Sorting:** domains and IPs are keyed once and sorted in bulk instead of
  re-deriving label order / re-parsing addresses inside every comparison
  (`domainCompare` allocated two slices per call). Global lists are sorted
  once and category lists are derived from the sorted result instead of being
  sorted again.
- **Conditional fetches:** sources are requested with `If-None-Match` /
  `If-Modified-Since`. When no source, custom list or exclusion list changed,
  the refresh keeps the current snapshot without parsing or rebuilding. A
  source that fails the same way as on the previous attempt does not force a
  rebuild either.
- **Merging:** deduplication and first-source-wins category assignment come
  from a single sort per stream instead of per-entry owner maps.
- **Parsing:** plain-text lists are parsed in a single pass without
  intermediate line/token slices or a separate comment-stripping copy; CSV is
  streamed; hosts-file field splitting and domain validation no longer
  allocate.
- **Memory:** category snapshots share slices instead of copying them, the
  download buffer is sized from `Content-Length`, and memory is returned to
  the OS after a rebuild.
- **Locking:** a refresh no longer holds the snapshot lock while downloading,
  so `/manage` exclusion edits stay responsive during a refresh.
- **Chunk responses:** `ETag` is now a content hash, so a chunk keeps its ETag
  across refreshes that did not change it, and `If-None-Match` is answered
  with `304 Not Modified`. Bodies are written in one call.
- `POST /refresh` returns `409` while another refresh is running instead of
  queueing a duplicate.
- `/stats` `updated_at` is the time the lists last changed upstream, not the
  time of the last check.
- CI: formatting, `go vet` and `go test -race` now run before the image build,
  every GitHub Action is pinned to a full commit SHA, and checkout no longer
  persists credentials.

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
