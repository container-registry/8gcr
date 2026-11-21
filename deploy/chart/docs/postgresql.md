# In-cluster PostgreSQL

For installs without CloudNativePG or a managed database, the chart can run
PostgreSQL itself with the
[cloudpirates/postgres](https://github.com/CloudPirates-io/helm-charts/tree/main/charts/postgres)
subchart and the official `postgres` image:

```yaml
postgresql:
  enabled: true
```

Harbor connects to the `postgresql` Service as `postgres`, database
`registry`, with `postgres-password` from the `postgresql` Secret. The subchart
generates that password unless you set `postgresql.auth.password` or
`postgresql.auth.existingSecret`. `database.*` is ignored. Any other
cloudpirates/postgres value can be set under `postgresql:`.

## Upgrading from a 2.15 chart

A release installed from a harbor-next 2.15 chart stores values with no
`postgresql.enabled`. With `helm upgrade --reuse-values`, Helm keeps those old
values and skips the new chart defaults, so Helm would deploy the subchart
nobody asked for. The chart refuses that upgrade with an error. Pass your
values file (`helm upgrade -f values.yaml`) or use `--reset-then-reuse-values`
(Helm 3.14+); both pick up the new defaults, including
`postgresql.enabled: false`.

## Major upgrades

The chart runs PostgreSQL 19, with the data in `19/docker` on the volume. An
init container, `pgdata-upgrade`, runs the chart's `files/pg-upgrade.sh` from
the `postgresql-upgrade` ConfigMap and checks the volume before PostgreSQL
starts:

- Empty, or already `19/docker`: nothing to do.
- `18/docker` (charts up to 2.16): it runs `pg_upgrade --link` from the
  [tianon/postgres-upgrade](https://github.com/tianon/docker-postgres-upgrade)
  `18-to-19` image, which carries both versions' binaries. The new cluster
  keeps the old superuser, encoding, locale, data checksum setting and WAL
  segment size, and takes over `pg_hba.conf`, `pg_ident.conf` and
  `postgresql.auto.conf`. It is built in `19/upgrade` and renamed to
  `19/docker` only when everything succeeded, so a pod restart in the middle
  starts the upgrade over. A PostgreSQL 18 that was killed instead of stopped
  is recovered first. Link mode hard-links the data files, so it needs little
  extra space and is fast on large databases.
- Anything older (`NN/docker`, `NN/data`, or `pgdata` and `pgdata/pgNN` from
  older layouts): it logs where it found the data and exits with an error, and
  the pod stays in `Init`. Without that check PostgreSQL 19 would start an empty
  database next to data in the `pgdata` layouts. Upgrade those with the 2.16
  chart first, which brings them to PostgreSQL 18 in `18/docker`.

Take a dump before you upgrade the chart. Once PostgreSQL 19 has started on
the linked files, the PostgreSQL 18 copy can no longer be started, and the
dump is the only way back. Stop Harbor's writers first, so nothing is written
after the dump. `helm upgrade` starts them again, and they wait for the
database until the upgrade is done. The release is called `harbor` in
namespace `harbor` here:

```sh
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0 &&
kubectl -n harbor wait --for=delete pod --timeout=5m \
  -l 'app.kubernetes.io/instance=harbor,app.kubernetes.io/component in (core,jobservice)' &&
kubectl -n harbor exec postgresql-0 -c postgresql -- \
  sh -c 'pg_dump -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB"' > harbor.sql &&
grep -q -- '-- PostgreSQL database dump complete' harbor.sql &&
helm upgrade harbor <chart> -n harbor -f values.yaml
```

Each step runs only when the one before succeeded, so a failed shutdown or an
incomplete dump stops before the upgrade. With `core.autoscaling` or
`jobservice.autoscaling` enabled, the chart sets no replica count and the HPA
does not scale up from 0, so run
`kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1`
after `helm upgrade`. Then check
`kubectl -n harbor logs postgresql-0 -c pgdata-upgrade`: the last line starts
with `upgraded 18/docker to 19/docker`. When Harbor works, remove
the old directory, which still holds the PostgreSQL 18 catalog:

```sh
kubectl -n harbor exec postgresql-0 -c postgresql -- rm -rf /var/lib/postgresql/18
```

Changes made directly in the old `postgresql.conf` are not carried over;
settings passed by the subchart or set with `ALTER SYSTEM` are. Keep
`harbor.sql` and the chart's `secretKey` together until the upgraded Harbor
works.

To stay on PostgreSQL 18 instead, pin `postgresql.image.tag` to an 18 tag and
set `postgresql.initContainers` to the pgautoupgrade 18 init container from the
2.16 chart's `values.yaml`. Use `[]` only when the volume already holds
`18/docker`; the pgautoupgrade init container is what moves older layouts there.
The chart refuses an image tag other than 19 while `pgdata-upgrade` is set,
because PostgreSQL 18 cannot start on the data it leaves behind. A values file
carried over from 2.16 with an 18 tag hits that check: drop the tag.

The chart also refuses to render when the init container would not find the
data or its script:

- With `postgresql.persistence.subPath` or `volumeName` set, give the init
  container's data mount the same values. Otherwise the init container misses
  the old data and PostgreSQL starts empty.
- When you set your own `postgresql.extraVolumes`, keep the `pg-upgrade`
  volume from `values.yaml` in the list.

### If the upgrade fails

The pod stays in `Init`. Until the new cluster is renamed to `19/docker`,
the only change to `18/docker` is pg_upgrade's rename of `global/pg_control`
to `pg_control.old`, which the next run undoes. Fix the cause shown in
`kubectl -n harbor logs postgresql-0 -c pgdata-upgrade` and the next pod start
retries. To go back to the 2.16 chart instead, for example after
`helm upgrade --atomic` rolled back in the middle of the upgrade, first put the
old cluster back in the state 2.16 expects:

```sh
kubectl -n harbor exec postgresql-0 -c postgresql -- sh -c \
  'cd /var/lib/postgresql && rm -rf 19/upgrade &&
   if [ -f 18/docker/global/pg_control.old ]; then mv 18/docker/global/pg_control.old 18/docker/global/pg_control; fi'
```

Run it from a debug pod on the PVC if `postgresql-0` does not start. This
only works while there is no `19/docker`. Once PostgreSQL 19 has started,
restore the dump into an empty volume. With `persistence.existingClaim`, point it at a
new, empty claim instead of deleting the PVC:

```sh
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0
kubectl -n harbor scale statefulset postgresql --replicas=0
kubectl -n harbor delete pvc data-postgresql-0
kubectl -n harbor scale statefulset postgresql --replicas=1
kubectl -n harbor wait --for=condition=Ready pod/postgresql-0 --timeout=5m
kubectl -n harbor exec -i postgresql-0 -c postgresql -- \
  sh -c 'psql -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB" -q -v ON_ERROR_STOP=1' < harbor.sql
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1
```

## Moving from goharbor/harbor-helm with the internal database

The old chart cannot be upgraded in place (Deployment selectors differ), so
uninstall it and install this chart under the same release name. The data
stays on the old `database-data-<release>-database-0` PVC. Install the 2.16
chart for this move: its init container moves the old data directory to
`18/docker` and upgrades it to PostgreSQL 18 when it is older. The old image
used another glibc, so on the first start it also runs `reindexdb --all` and
`ALTER DATABASE ... REFRESH COLLATION VERSION`. Later starts find nothing to
do. Then upgrade to this chart, which takes `18/docker` to PostgreSQL 19 as
described in [Major upgrades](#major-upgrades). This chart refuses the old
directory and does not move it.

| Harbor | harbor-helm | PostgreSQL | Data directory on the PVC |
|---|---|---|---|
| 2.8 | 1.12 | 13 | `pgdata/pg13` |
| 2.9 to 2.10 | 1.13 to 1.14 | 14 | `pgdata/pg14` |
| 2.11 to 2.15.1 | 1.15 to 1.19.1 | 15 | `pgdata/pg15` |
| 2.15.2 and newer | 1.19.2 and newer | 18 | `pgdata/pg18` |

Check yours with
`kubectl -n harbor exec harbor-database-0 -c database -- ls /var/lib/postgresql/data/pgdata`.

1. Read the old secrets and take a backup:

   ```sh
   kubectl -n harbor get secret harbor-database -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d
   kubectl -n harbor get secret harbor-core -o jsonpath='{.data.secretKey}' | base64 -d
   kubectl -n harbor exec harbor-database-0 -c database -- pg_dumpall -U postgres > all.sql
   ```

2. `helm uninstall harbor -n harbor`. The database PVC and `harbor-registry`
   stay.

3. Install with:

   ```yaml
   secretKey: <secretKey>
   registry:
     persistence:
       enabled: true
       existingClaim: harbor-registry
   postgresql:
     enabled: true
     auth:
       password: <POSTGRES_PASSWORD>
     persistence:
       existingClaim: database-data-harbor-database-0
   ```

## Going back to goharbor/harbor-helm

Uninstall this chart first: `helm uninstall harbor -n harbor`.

Once the data is PostgreSQL 19, only the dump from step 1 brings you back.
While it is still on the 2.16 chart:

If the old data was PostgreSQL 15 or older, it is PostgreSQL 18 now and the
old image cannot read it. Restore the dump from step 1 into a fresh old
install. Anything written after the move is lost. The harbor-db image has
no `tar` before 2.15.2, so the dump goes through `kubectl exec`, not
`kubectl cp`.

```sh
kubectl -n harbor delete pvc database-data-harbor-database-0
helm install harbor harbor/harbor --version <old chart> -n harbor -f old-values.yaml --wait
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0
kubectl -n harbor exec harbor-database-0 -c database -- psql -U postgres -c 'DROP DATABASE registry WITH (FORCE)'
kubectl -n harbor exec -i harbor-database-0 -c database -- psql -U postgres -q < all.sql
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1
```

The restore prints `ERROR:  role "postgres" already exists`, which is
harmless.

If the old data was already PostgreSQL 18 (`pgdata/pg18`), move it back and
reinstall the old chart with the old values:

```sh
kubectl -n harbor apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: pg-move-back
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 999
    runAsGroup: 999
  containers:
    - name: mv
      image: docker.io/library/busybox:1.37
      command: ["sh", "-ec", "mkdir -p /data/pgdata && mv /data/18/docker /data/pgdata/pg18 && rmdir /data/18"]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: database-data-harbor-database-0
YAML
kubectl -n harbor wait --for=jsonpath='{.status.phase}'=Succeeded pod/pg-move-back
kubectl -n harbor delete pod pg-move-back
helm install harbor harbor/harbor --version <old chart> -n harbor -f old-values.yaml --wait
```

Moving the directory back only works while the Harbor schema is still the
old release's. Check it with `SELECT version FROM schema_migrations` before
you uninstall this chart. 8gcr 2.15 keeps schema 181, the same as
upstream 2.15.3, and upstream core starts on it with `No change in schema,
skip.`. 8gcr 2.16 migrates to 190, and upstream 2.15 core then exits
with `failed to migrate the database, error: no migration found for version
190`. Then the dump is the only way back. Tables that 8gcr adds stay in the
database and upstream ignores them.
