# dns-ip-list-chunker

Fetches and merges DNS/IP blocklists (and optional allowlists), then re-serves
them as plain-text chunks sized for DNS servers and routers that reject
oversized external blocklists or allowlists.

Formerly `unifi-blocklist-chunker` — same engine, generic naming.

## How it works

1. Sources come from `BLOCKLIST_URLS` (optional `category:https://…` tags) and/or
   inline `custom_blocklists` in `LISTS_FILE`. Formats: **txt**, **hosts**,
   **adblock**, **JSON**, **YAML**, **TOML**, **CSV**. Line comments (`#`,
   `//`, `--`, `;`) strip only at line start or after whitespace so labels
   like `xn--…` and `o--o.example` survive; CIDRs keep a single `/`.
2. Entries are normalized and classified as **domains**, **IPv4**, or **IPv6**.
3. Deduplicated entries join the global **all** feed and exactly **one** block
   category (first source wins). Feeds are sorted and split into chunks of at
   most `CHUNK_SIZE`.
4. `exclusion_lists` in `LISTS_FILE` (and `EXCLUSIONS_URLS` / `/manage`) withhold
   matches from block feeds when they are pure exclusions. Lists with
   `output_allowlist: true` publish `/allowlists/<category>/…` for routers/DNS
   that subscribe to allowlists; those entries are stripped from block feeds
   only when `ALLOWLIST_ALSO_EXCLUDES=true` (default off — so you can apply
   allow feeds to some clients while leaving the global blocklist intact).
5. A failed URL source is skipped; other sources still apply.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /` | Index of **all** block URLs, per-category block URLs, then allowlists |
| `GET /lists/dns-<n>.txt` | Global domain chunk |
| `GET /lists/ipv4-<n>.txt` / `ipv6-<n>.txt` | Global IP chunks |
| `GET /lists/<category>/dns-<n>.txt` | Category block chunk (also `ipv4` / `ipv6`) |
| `GET /allowlists/<category>/dns-<n>.txt` | Optional allowlist chunk |
| `GET /stats` | JSON counts, `categories`, `allowlists` |
| `GET /search?q=` | Lookup (includes `category` when known) |
| `GET /manage` | Search / exclude / restore UI (needs `ADMIN_TOKEN`) |
| `GET`/`POST`/`DELETE /exclusions` | Exclusion API (admin auth) |
| `POST /refresh` | Re-check sources now (`409` if a refresh is already running) |
| `GET /healthz` | Liveness |

## Configuration (environment)

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `BLOCKLIST_URLS` | *(none)* | one of URLs or `LISTS_FILE` | Upstream list URLs. Optional `category:https://…`. Separators: comma, space, tab, newline. |
| `LISTS_FILE` | *(unset)* | one of URLs or file | YAML/JSON with `custom_blocklists` and `exclusion_lists` (inline multiline `entries`). |
| `CHUNK_SIZE` | `100000` | no | Max entries per chunk. |
| `PORT` | `8080` | no | Listen port. |
| `REFRESH_INTERVAL` | `6h` | no | Re-check interval; `0` = manual only. Sources are fetched with `If-None-Match` / `If-Modified-Since`; when every source answers `304 Not Modified` nothing is re-parsed or rebuilt. |
| `BASE_URL` | *(unset)* | no | Public origin for generated links; else `X-Forwarded-*`. |
| `ADMIN_TOKEN` | *(unset)* | no | Gates `/manage` and exclusion mutations (fail-closed if unset). |
| `EXCLUSIONS_FILE` | `exclusions.json` | no | Internal persistence for `/manage` exclusions (not a seed format). |
| `EXCLUSIONS_URLS` | *(unset)* | no | Remote exclusion list URLs (same formats as blocklists). |
| `ALLOWLIST_ALSO_EXCLUDES` | `false` | no | When `true`, entries from `output_allowlist` lists are also withheld from exported block feeds. Default keeps allowlisted entries in blocklists so allow feeds can be applied per-client. |

### `LISTS_FILE` example

```yaml
custom_blocklists:
  - name: corp-extra
    category: custom
    entries: |
      ads.example.com
      203.0.113.0/24
exclusion_lists:
  - name: family-allow
    category: allow-family
    output_allowlist: true
    entries: |
      school.edu
      10.0.0.0/8
```

### Categories on URLs

```text
BLOCKLIST_URLS=threat:https://example.com/threat.txt,dns-blocklisting:https://example.com/dns.txt
```

## Run

Published images (after rename):

- GHCR: `ghcr.io/charlestephen/dns-ip-list-chunker:latest`
- Docker Hub: `docker.io/charlestephen/dns-ip-list-chunker:latest`

```sh
podman run -d --name dns-ip-list-chunker \
  -e BLOCKLIST_URLS='threat:https://example.com/list.txt' \
  -e ADMIN_TOKEN='replace-me' \
  -e EXCLUSIONS_FILE=/data/exclusions.json \
  -v dns-ip-list-chunker-data:/data \
  -p 8080:8080 \
  ghcr.io/charlestephen/dns-ip-list-chunker:latest
```

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Home Assistant

Home Assistant app wrapper:
[dns-ip-list-chunker](https://github.com/charlestephen/hassio-apps/tree/main/dns-ip-list-chunker)
in [hassio-apps](https://github.com/charlestephen/hassio-apps).

[![Open your Home Assistant instance and show the dashboard of an app.](https://my.home-assistant.io/badges/supervisor_addon.svg)](https://my.home-assistant.io/redirect/supervisor_addon/?addon=dns_ip_list_chunker&repository_url=https%3A%2F%2Fgithub.com%2Fcharlestephen%2Fhassio-apps)

## License

MIT — see [LICENSE](LICENSE).
