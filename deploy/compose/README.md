# Harbor Compose

Minimal Docker Compose deployment for Harbor

## Prerequisites

- Docker Engine 24+ with Compose v2.24+
- Harbor images — pulled from `8gears.container-registry.com/8gcr/` by default, or built locally with `task image:all-images`

## Quick Start

```bash
cd deploy/compose

# 1. Configure environment
cp .env.example .env
# Edit .env — set EXT_ENDPOINT, TLS_CERT, TLS_KEY, and all secrets

# 2. Generate token signing key (must be PKCS#1 / "RSA PRIVATE KEY" format)
openssl genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:4096 \
  | openssl rsa -traditional -out config/token_service_key.pem
chmod 644 config/token_service_key.pem   # container UID 10000 ≠ host UID → needs world-readable

# 3. Generate the secret key Core uses to encrypt stored credentials (exactly 16 alphanumeric chars).
#    Generated once; see "Secret Key" below before touching an existing one.
[ -f config/secret_key ] || openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 16 > config/secret_key
chmod 644 config/secret_key

# 4. Start. --remove-orphans also stops the registryctl container left over
#    from releases before the registry served the GC API itself.
docker compose up -d --remove-orphans

# 5. Verify
docker compose ps
curl https://registry.example.com/api/v2.0/systeminfo
```

## Secret Key

`config/secret_key` is the AES key Core uses to encrypt credentials stored in
the database (replication endpoints, scanner credentials, OIDC secrets). It
belongs to the database for the lifetime of the install: back it up together
with the `postgres-data` volume and never regenerate it while that volume
exists. With a different key Harbor cannot decrypt the stored credentials, the
same invariant the Helm chart documents for `secretKey` in
[`deploy/chart/docs/MIGRATION.md`](../chart/docs/MIGRATION.md).

**Upgrading an existing deployment.** Compose files before this one did not
mount the key, so an existing install has no `config/secret_key`. Create it once
with step 3 above before the first `docker compose up` on the new version, then
keep it. The mount is declared with `create_host_path: false`, so a missing
file fails the start instead of being created as an empty directory.

## PostgreSQL 19

The bundled database runs `postgres:19-alpine`. The `postgres-data` volume is
mounted at `/var/lib/postgresql` and the data lives in `19/docker` inside it,
the layout the PostgreSQL 19 image expects. The version is fixed in the
compose file and `POSTGRES_VERSION` is not read, because an older image on
this mount would ignore the existing data and start an empty database.

Before the database starts, the one-shot `postgresql-upgrade` service checks
the volume with `deploy/chart/files/pg-upgrade.sh`, the script the Helm chart
runs too. A volume from the previous compose file, with PostgreSQL 18 data in
`18/docker`, is upgraded in place with `pg_upgrade --link` from the
`tianon/postgres-upgrade:18-to-19` image. The new cluster keeps the old
superuser, encoding, locale, data checksum setting and WAL segment size, and
takes over `pg_hba.conf`, `pg_ident.conf` and `postgresql.auto.conf`. Changes
made directly in the old `postgresql.conf` are not carried over: set them
again with `ALTER SYSTEM`. `max_connections` is the exception. The compose
file starts postgres with `-c max_connections=1024`, which overrides both
config files, so change that value in the `command` of the `postgresql`
service or in a compose override file.
An empty volume or one already on 19 is left alone. Older data (a volume from
PostgreSQL 16 or 15 at `/var/lib/postgresql/data`) makes the service fail with
the directory it found; move it with a `pg_dump` from the old container and a
`psql` restore into a fresh volume, as below.

Dump the database before you update the compose file. After PostgreSQL 19
starts on the linked files, the PostgreSQL 18 copy can no longer be started:

```bash
cd deploy/compose

# 1. With the OLD compose file: stop Harbor's writers, dump the database
docker compose stop core jobservice &&
docker compose exec -T postgresql \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > harbor.sql &&
grep -q -- '-- PostgreSQL database dump complete' harbor.sql && echo "dump OK"

# 2. Only after "dump OK": switch to the new compose file, then restart.
#    The upgrade runs before the database.
grep -q -- '-- PostgreSQL database dump complete' harbor.sql &&
docker compose down &&
docker compose up -d
docker compose logs postgresql-upgrade
```

The last log line starts with `upgraded 18/docker to 19/docker`. When Harbor
works, the old `18` directory on the volume can go:

```bash
docker compose exec postgresql rm -rf /var/lib/postgresql/18
```

Keep `harbor.sql` and `config/secret_key` together until the upgraded Harbor
works. If the upgrade fails, fix the cause shown in its log and run
`docker compose up -d` again: it retries from the start. Until the new cluster
is renamed to `19/docker`, the old compose file can still start `18/docker`. Once PostgreSQL 19 has
started, the dump is the only way back. Empty the database volume and restore
it; Harbor starts only when the restore succeeded:

```bash
docker compose down &&
docker compose run --rm --no-deps --entrypoint sh postgresql -c 'rm -rf /var/lib/postgresql/*' &&
docker compose up -d --wait postgresql &&
docker compose exec -T postgresql \
  sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q -v ON_ERROR_STOP=1' < harbor.sql &&
docker compose up -d
```

## TLS Certificates

TLS is enabled by default. Set `TLS_CERT` and `TLS_KEY` in `.env` to absolute paths on the host:

```bash
TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem
TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem
```

**Obtain certificates with Let's Encrypt:**

```bash
certbot certonly --standalone -d registry.example.com
```

**Or generate a self-signed certificate for testing:**

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout config/certs/tls.key -out config/certs/tls.crt \
  -subj "/CN=registry.example.com"
```

When using self-signed certs, Docker clients require `--insecure-registry` or the CA must be trusted on each host.

**Non-default HTTPS port.** Plain HTTP on `PORT_HTTP` redirects to HTTPS, and nginx
cannot read `PORT_HTTPS` from the environment. When `PORT_HTTPS` is not `443`, copy
`config/nginx/tls.conf`, set `$https_port` in the copy to the same port, and point
`TLS_CONF` at it:

```bash
mkdir -p config
sed 's/^set \$https_port 443;/set $https_port 8443;/' ../../config/nginx/tls.conf > config/tls.conf
# .env
PORT_HTTPS=8443
TLS_CONF=./config/tls.conf
```

## Image Repository

`.env.example` defaults to pulling from the remote registry (`8gears.container-registry.com/8gcr/`).
To use locally built images instead, set `IMAGE_REPO=` (empty) in `.env`.

Images resolve to `${IMAGE_REPO}harbor-core:${HARBOR_TAG}`, so the value must end with `/`.

Keep `HARBOR_TAG` in step with this compose file. Its portal healthcheck probes
`127.0.0.1:8081/healthz`, which older portal images do not serve, so an older
portal image stays `unhealthy` even though it works. Pull or build a portal image
from the same version when updating the compose file.

## Registry Proxy

Set `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` in `.env` when the Registry
service must reach upstream registries through a proxy. Include Harbor's
internal service names in `NO_PROXY`, for example:

```env
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=http://proxy.example.com:8080
NO_PROXY=localhost,127.0.0.1,core,registry
```

## Architecture

Portal (nginx) serves the Angular UI and reverse-proxies `/v2/`, `/api/`, `/service/`, and `/c/` to Core.

<!--
```SVGBob
                          ":443 (HTTPS)  /  :80 (HTTP)"
                                      │
                                      ▼
                              ┌────────────────┐
                              │    "Portal"    │
                              │    "(nginx)"   │
                              └───────┬────────┘
                                      │
                                      ▼
                              ┌────────────────┐
                              │     "Core"     │
                              │    ":8080"     │
                              └──┬──────────┬──┘
                  ┌──────────────┘          │
                  ▼                         ▼
          ┌───────────────┐         ┌───────────────┐
          │ "JobService"  │-------->│  "Registry"   │
          │    ":8888"    │         │    ":5000"    │
          └───────────────┘         └───────┬───────┘
                                            │
                                            ▼
                                    ┌────────────────┐
                                    │"registry-data" │
                                    │   "(volume)"   │
                                    └────────────────┘

          ┌───────────────┐   ┌───────────────┐
          │    "Trivy"    │   │  "Exporter"   │
          │   "Adapter"   │   │               │
          └───────────────┘   └───────────────┘

          ┌───────────────┐   ┌───────────────┐
          │ "PostgreSQL"  │   │    "Redis"    │
          │    ":5432"    │   │    ":6379"    │
          └───────────────┘   └───────────────┘
```
-->
![Diagram](https://kroki.io/svgbob/svg/eNpTUMAFlKxMTIwVNDxCQgKCNRUU9BUUrCwMIHxNJS4FosCjKU3Eqpy2h4uQWT2PpjSQiCYQNLQJ7NeA_KKSxBwl4twM06SRl56ZV6GpRKSmKTjcuAa382cMs3BWUHLOL0pVUiAtnIHpzsKAeE1TiAhYNAXYwpnEcJhBKDaAIU9krJAeAxMo0cuFGuJKXvlJwalFZZnJoIgCiuhCgR04PpSCUtMzi0uKKjGTPSK-gEAJOdpRZE0NDAyw5DTcGYRwkJOeuYjNWaTmL2JzGQ3zGtzJSkXQqNJNSSxJVCLaF5CYUtIoy88pzU0lsnwjNxLBcUFx4qc82YN8HFKUWVaJlHAhCd61ogBYO6QW4UrwSo4piQUIebRkjy0BkZfUydA1GAIWWLcWl6QXpQYH-iihBRCwLEnJLMZaFsDKChNjI_QIAYmbGZtbKg1gwAIA5C6Weg==)

- **Portal (nginx)** — serves the static Angular UI and reverse-proxies `/v2/*`, `/api/*`, `/service/*`, and `/c/*` to Core.
- **Core** (`:8080`) — API gateway, authentication, and business logic.
- **JobService** (`:8888`) — asynchronous jobs (scan, replication, GC, retention).
- **Registry** (`:5000`) — `distribution/distribution` with the patches in `patches/distribution`; blob/manifest storage, plus the GC delete API (`/api/registry/*`) that JobService calls.
- **registry-data** — Docker volume mounted at `/var/lib/registry`.
- **Trivy Adapter** — vulnerability scanner. **Exporter** — Prometheus `/metrics`.
- **Infrastructure** — PostgreSQL (`:5432`) and Redis/Valkey (`:6379`) are shared by Core, JobService, Trivy, and Exporter.

## Verify Push/Pull

```bash
echo '<your-admin-password>' | docker login registry.example.com -u admin --password-stdin
docker tag alpine:latest registry.example.com/library/alpine:test
docker push registry.example.com/library/alpine:test
docker pull registry.example.com/library/alpine:test
```
