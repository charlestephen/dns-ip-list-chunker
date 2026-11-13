# dns-ip-list-chunker

Fetches and merges DNS/IP blocklists (and optional allowlists), then re-serves them as plain-text chunks sized for DNS servers and routers that reject oversized external lists.

It is a single static Go binary in a `scratch` image (`linux/amd64` and `linux/arm64`), running as UID/GID 65534. Formerly `unifi-blocklist-chunker`.

- Source and full documentation: https://github.com/charlestephen/dns-ip-list-chunker
- Issues: https://github.com/charlestephen/dns-ip-list-chunker/issues
- Also published at `ghcr.io/charlestephen/dns-ip-list-chunker`

## Tags

| Tag | Meaning |
|---|---|
| `latest` | Most recent release. |
| `1.6`, `1.6.0` | A release, by minor or exact version. |
| `sha-<commit>` | The image built from that commit. |

## Quick start

```bash
docker run -d --name dns-ip-list-chunker --restart unless-stopped \
  -e BLOCKLIST_URLS='threat:https://example.com/list.txt' \
  -e ADMIN_TOKEN='replace-me' \
  -e EXCLUSIONS_FILE=/data/exclusions.json \
  -v dns-ip-list-chunker-data:/data \
  -p 8080:8080 \
  charlestephen/dns-ip-list-chunker:latest
```

Replace `https://example.com/list.txt` with your source list and `replace-me` with a long random token. The token protects the `/manage` page and the exclusion API. If you leave it unset, those are disabled.

Open `http://localhost:8080/` for an index of every chunk URL, then point your DNS server or router at one of them, for example `http://<host>:8080/lists/dns-1.txt`.

To update:

```bash
docker pull charlestephen/dns-ip-list-chunker:latest
docker rm -f dns-ip-list-chunker
# then run the docker run command above again
```

### Docker Compose

```yaml
services:
  dns-ip-list-chunker:
    image: charlestephen/dns-ip-list-chunker:latest
    restart: unless-stopped
    environment:
      BLOCKLIST_URLS: "threat:https://example.com/threat.txt,https://example.com/ip-blocklist.txt"
      CHUNK_SIZE: "100000"
      REFRESH_INTERVAL: "6h"
      ADMIN_TOKEN: "${ADMIN_TOKEN:-}"
      EXCLUSIONS_FILE: "/data/exclusions.json"
    volumes:
      - dns-ip-list-chunker-data:/data
    ports:
      - "8080:8080"

volumes:
  dns-ip-list-chunker-data:
```

```bash
export ADMIN_TOKEN='replace-me'
docker compose up -d
docker compose pull && docker compose up -d   # update
```

## How it works

1. Sources come from `BLOCKLIST_URLS` (optional `category:https://...` tags) and/or inline `custom_blocklists` in a `LISTS_FILE`. Supported formats: txt, hosts, AdGuard/adblock, JSON, YAML, TOML and CSV.
2. Entries are normalized and classified as domains, IPv4 or IPv6, then deduplicated.
3. Each entry joins the global feed and exactly one category (the first source wins). Feeds are sorted and split into chunks of at most `CHUNK_SIZE` entries.
4. Exclusion lists and allowlists withhold entries from the block feeds, or publish them as separate allowlist feeds.
5. A source that fails to download is skipped, and the others still apply.

## Volumes and ports

| Path / port | Purpose |
|---|---|
| `/data` | Stores `exclusions.json` (set `EXCLUSIONS_FILE=/data/exclusions.json`) so `/manage` exclusions survive restarts. The image runs as UID 65534, so use a named volume as shown, or make a bind-mounted directory writable by that user. |
| `8080/tcp` | HTTP server for the chunks, the index, `/stats` and `/healthz`. Change it with `PORT`. |

## Configuration (environment)

| Variable | Default | Description |
|---|---|---|
| `BLOCKLIST_URLS` | none | Upstream list URLs, optionally `category:https://...`. Separate with commas, spaces, tabs or newlines. Required unless `LISTS_FILE` is set. |
| `LISTS_FILE` | unset | YAML or JSON file with `custom_blocklists` and `exclusion_lists`. Mount it into the container and set this to its path. |
| `CHUNK_SIZE` | `100000` | Maximum entries per chunk. |
| `PORT` | `8080` | Listen port inside the container. |
| `REFRESH_INTERVAL` | `6h` | How often sources are re-checked. `0` means manual only. Unchanged sources (HTTP 304) are not re-parsed. |
| `BASE_URL` | unset | Public origin used in generated links. Otherwise `X-Forwarded-*` headers are used. |
| `ADMIN_TOKEN` | unset | Protects `/manage` and the exclusion API. Unset disables them. |
| `EXCLUSIONS_FILE` | `exclusions.json` | Where `/manage` exclusions are saved. |
| `EXCLUSIONS_URLS` | unset | Remote exclusion list URLs. |
| `ALLOWLIST_ALSO_EXCLUDES` | `false` | When `true`, allowlist entries are also removed from the block feeds. |

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
```

Run it with the file mounted:

```bash
docker run -d --name dns-ip-list-chunker -p 8080:8080 \
  -e LISTS_FILE=/config/lists.yaml \
  -v "$PWD/lists.yaml:/config/lists.yaml:ro" \
  charlestephen/dns-ip-list-chunker:latest
```

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Index of all block URLs, per-category block URLs, then allowlists. |
| `GET /lists/dns-<n>.txt`, `ipv4-<n>.txt`, `ipv6-<n>.txt` | Global chunks. |
| `GET /lists/<category>/dns-<n>.txt` | Per-category chunks. |
| `GET /allowlists/dns-<n>.txt` | All allowlists merged. |
| `GET /stats` | JSON counts. |
| `GET /search?q=` | Look up an entry. |
| `GET /manage` | Search, exclude and restore UI (needs `ADMIN_TOKEN`). |
| `POST /refresh` | Re-check sources now. |
| `GET /healthz` | Liveness. |

## Logs and health

The image has no shell, so `docker exec` into it will not work. Use:

```bash
docker logs -f dns-ip-list-chunker
curl -fs localhost:8080/healthz
curl -s localhost:8080/stats
```

## License

MIT. See https://github.com/charlestephen/dns-ip-list-chunker/blob/main/LICENSE
