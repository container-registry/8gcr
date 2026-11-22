# In-cluster PostgreSQL

This page is for operators who run Harbor on the chart's bundled PostgreSQL
(`postgresql.enabled: true`) because they have no CloudNativePG or managed
database. It explains how to turn it on, how to upgrade the chart when the
PostgreSQL major version changes, what to do when that upgrade fails, and how
to move to or from the goharbor/harbor-helm chart.

With CloudNativePG or a managed database, the chart only connects to it
through `database.*`; it does not run PostgreSQL or upgrade it, and nothing on
this page applies. See the [K3S guide](guide/k3s.md) for a CloudNativePG setup
and the README's
[CloudNativePG via extraManifests](../README.md#cloudnativepg-via-extramanifests).

| You are | Read |
|---|---|
| Installing | [Enabling it](#enabling-it) |
| Upgrading from a 2.15 chart | [Upgrading from 2.15](#upgrading-from-215) |
| Upgrading from a 2.16 chart | [Upgrading PostgreSQL 18 to 19](#upgrading-postgresql-18-to-19) |
| Stuck after an upgrade | [If the upgrade fails](#if-the-upgrade-fails) |
| Coming from goharbor/harbor-helm | [Moving from goharbor/harbor-helm](#moving-from-goharborharbor-helm) |
| Going back to goharbor/harbor-helm | [Going back to goharbor/harbor-helm](#going-back-to-goharborharbor-helm) |

The examples use release `harbor` in namespace `harbor`.

## Enabling it

```yaml
postgresql:
  enabled: true
```

The chart then deploys the
[cloudpirates/postgres](https://github.com/CloudPirates-io/helm-charts/tree/main/charts/postgres)
subchart with the official `postgres` image, PostgreSQL 19, and ignores
`database.*`. Harbor connects to the `postgresql` Service as `postgres`,
database `registry`, with the `postgres-password` key of the `postgresql`
Secret. The subchart generates that password unless you set
`postgresql.auth.password` or `postgresql.auth.existingSecret`. Any other
cloudpirates/postgres value goes under `postgresql:`.

An init container, `pgdata-upgrade`, checks the volume before every start (see
[below](#upgrading-postgresql-18-to-19)). The chart refuses to render values
that would make it miss the data:

- If you set `postgresql.persistence.subPath` or `volumeName`, give the init
  container's data mount the same values. Otherwise it looks at an empty
  directory and PostgreSQL starts an empty database.
- If you set your own `postgresql.extraVolumes`, keep the `pg-upgrade` volume
  from `values.yaml`. It holds the init container's script.
- `postgresql.image.tag` must be a 19 tag while `pgdata-upgrade` is set. See
  [staying on PostgreSQL 18](#staying-on-postgresql-18).

## Upgrading from 2.15

`helm upgrade --reuse-values` from a harbor-next 2.15 chart fails on purpose.
The stored 2.15 values have no `postgresql.enabled`, and Helm would skip the
new default and deploy a database nobody asked for. Pass your values file
(`helm upgrade -f values.yaml`) or use `--reset-then-reuse-values` (Helm 3.14
and newer) instead.

## Upgrading PostgreSQL 18 to 19

Charts up to 2.16 run PostgreSQL 18 with the data in `18/docker` on the
volume. This chart runs PostgreSQL 19 in `19/docker` and upgrades the old data
on the first start. The `pgdata-upgrade` init container runs the chart's
`files/pg-upgrade.sh`, which calls `pg_upgrade --link` from the
[tianon/postgres-upgrade](https://github.com/tianon/docker-postgres-upgrade)
`18-to-19` image. Link mode hard-links the data files instead of copying them,
so it needs little extra space and is fast on large databases. After
PostgreSQL 19 has started on those files, PostgreSQL 18 cannot start them
again, so the dump you take first is the only way back.

The new cluster keeps the old superuser, encoding, locale, data checksum
setting and WAL segment size, and takes over `pg_hba.conf`, `pg_ident.conf`
and `postgresql.auto.conf`. Settings passed by the subchart or set with
`ALTER SYSTEM` survive; edits made directly in the old `postgresql.conf` do
not.

Stop Harbor's writers, dump the database and upgrade in one chain, so a failed
shutdown or an incomplete dump stops before the upgrade:

```sh
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0 &&
kubectl -n harbor wait --for=delete pod --timeout=5m \
  -l 'app.kubernetes.io/instance=harbor,app.kubernetes.io/component in (core,jobservice)' &&
kubectl -n harbor exec postgresql-0 -c postgresql -- \
  sh -c 'pg_dump -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB"' > harbor.sql &&
grep -q -- '-- PostgreSQL database dump complete' harbor.sql &&
helm upgrade harbor <chart> -n harbor -f values.yaml
```

`helm upgrade` starts core and jobservice again, and they wait for the
database until the upgrade is done. With `core.autoscaling` or
`jobservice.autoscaling` the chart sets no replica count and the HPA does not
scale up from 0, so scale them up yourself:
`kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1`.

`kubectl -n harbor logs postgresql-0 -c pgdata-upgrade` should end with a line
starting `upgraded 18/docker to 19/docker`. Keep `harbor.sql` and the chart's
`secretKey` together until Harbor works on the new version, then remove the
old directory, which still holds the PostgreSQL 18 catalog:

```sh
kubectl -n harbor exec postgresql-0 -c postgresql -- rm -rf /var/lib/postgresql/18
```

The init container decides by what it finds on the volume:

| The volume holds | `pgdata-upgrade` |
|---|---|
| Nothing, or `19/docker` | Does nothing. |
| `18/docker` | Builds the new cluster in `19/upgrade` and renames it to `19/docker` only when everything succeeded, so a restart in the middle starts over. A PostgreSQL 18 that was killed instead of stopped is recovered first. |
| `NN/docker`, `NN/data`, `pgdata` or `pgdata/pgNN` | Logs where it found the data and fails, and the pod stays in `Init`. PostgreSQL 19 would otherwise start an empty database next to that data. Upgrade with the 2.16 chart first, which brings it to PostgreSQL 18 in `18/docker`. |

### Staying on PostgreSQL 18

Pin `postgresql.image.tag` to an 18 tag and set `postgresql.initContainers` to
the pgautoupgrade 18 init container from the 2.16 chart's `values.yaml`. Use
`[]` only when the volume already holds `18/docker`, since the pgautoupgrade
init container is what moves older layouts there. Leaving `pgdata-upgrade` in
place with an 18 tag fails to render, because PostgreSQL 18 cannot start on
the data the upgrade leaves behind. A values file carried over from 2.16 with
an 18 tag hits this check; remove the tag to upgrade.

## If the upgrade fails

The pod stays in `Init`, and
`kubectl -n harbor logs postgresql-0 -c pgdata-upgrade` shows why. Fix the cause and the next pod start retries from
the beginning.

Until the new cluster is renamed to `19/docker`, PostgreSQL 18 can still start
`18/docker`. The script does touch it: it reads it in single-user mode, which
recovers and checkpoints it like a normal start, it removes a stale
`postmaster.pid`, and pg_upgrade renames `global/pg_control` to
`pg_control.old`. To go back to the 2.16 chart, for example after
`helm upgrade --atomic` rolled back in the middle of the upgrade, undo that
rename and drop the half-built cluster first:

```sh
kubectl -n harbor exec postgresql-0 -c postgresql -- sh -c \
  'cd /var/lib/postgresql && rm -rf 19/upgrade &&
   if [ -f 18/docker/global/pg_control.old ]; then mv 18/docker/global/pg_control.old 18/docker/global/pg_control; fi'
```

If `postgresql-0` does not start, run the same commands from a debug pod that
mounts the PVC.

Once `19/docker` exists, restore the dump into an empty volume instead. The
claim is `<postgresql.persistence.volumeName>-postgresql-0`,
`data-postgresql-0` by default. With `persistence.existingClaim`, point it at
a new, empty claim instead of deleting one. Harbor starts only when the
restore succeeded:

```sh
pvc=data-postgresql-0
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0 &&
kubectl -n harbor scale statefulset postgresql --replicas=0 &&
kubectl -n harbor wait --for=delete pod/postgresql-0 --timeout=5m &&
kubectl -n harbor delete pvc "$pvc" &&
kubectl -n harbor scale statefulset postgresql --replicas=1 &&
kubectl -n harbor rollout status statefulset/postgresql --timeout=5m &&
kubectl -n harbor exec -i postgresql-0 -c postgresql -- \
  sh -c 'psql -U "${POSTGRES_USER:-postgres}" -d "$POSTGRES_DB" -q -v ON_ERROR_STOP=1' < harbor.sql &&
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1
```

## Moving from goharbor/harbor-helm

goharbor/harbor-helm's internal database cannot be upgraded in place, because
the Deployment selectors differ. You uninstall it and install this chart under
the same release name, and the data stays on the old
`database-data-<release>-database-0` PVC. The move takes two chart versions.
The 2.16 chart moves the old data directory to `18/docker` and upgrades it to
PostgreSQL 18 when it is older; this chart refuses the old directory. Because
the old image used another glibc, the 2.16 chart also runs `reindexdb --all`
and `ALTER DATABASE ... REFRESH COLLATION VERSION` on the first start. Then
this chart takes `18/docker` to PostgreSQL 19.

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

3. Install the 2.16 chart with:

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

4. Upgrade to this chart as described in
   [Upgrading PostgreSQL 18 to 19](#upgrading-postgresql-18-to-19).

## Going back to goharbor/harbor-helm

Uninstall this chart first: `helm uninstall harbor -n harbor`. How you go back
depends on what is on the PVC now:

- PostgreSQL 19 data, or old data that was PostgreSQL 15 or older and is now
  18: the old image cannot read it. Restore `all.sql` from step 1 of the move
  into a fresh old install. Anything written since the move is lost.
- Old data that was already `pgdata/pg18`, still on the 2.16 chart, with the
  old release's Harbor schema: move the directory back.

To restore the dump:

```sh
kubectl -n harbor delete pvc database-data-harbor-database-0
helm install harbor harbor/harbor --version <old chart> -n harbor -f old-values.yaml --wait
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=0
kubectl -n harbor exec harbor-database-0 -c database -- psql -U postgres -c 'DROP DATABASE registry WITH (FORCE)'
kubectl -n harbor exec -i harbor-database-0 -c database -- psql -U postgres -q < all.sql
kubectl -n harbor scale deploy harbor-core harbor-jobservice --replicas=1
```

The dump goes through `kubectl exec` because the harbor-db image has no `tar`
before 2.15.2, so `kubectl cp` does not work. The restore prints
`ERROR:  role "postgres" already exists`, which is harmless.

Before moving the directory back, check the schema with
`SELECT version FROM schema_migrations`. 8gcr 2.15 keeps schema 181, the same
as upstream 2.15.3, and upstream core starts on it with
`No change in schema, skip.`. 8gcr 2.16 migrates to 190, and upstream 2.15
core then exits with
`failed to migrate the database, error: no migration found for version 190`;
restore the dump instead. Tables that 8gcr adds stay in the database, and
upstream ignores them.

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
