#!/bin/sh
# Upgrades PostgreSQL 18 data in 18/docker to 19/docker with pg_upgrade --link.
# Runs in tianon/postgres-upgrade:18-to-19 with the data volume as the working
# directory, as the chart's pgdata-upgrade init container and the compose
# postgresql-upgrade service. Both start it only after the old server is gone.
set -eu

[ -s 19/docker/PG_VERSION ] && exit 0
if [ ! -s 18/docker/PG_VERSION ]; then
  for d in . data [0-9]*/docker [0-9]*/data pgdata pgdata/pg[0-9]*; do
    [ -s "$d/PG_VERSION" ] || continue
    echo "found PostgreSQL $(cat "$d/PG_VERSION") data in $d; only 18/docker is upgraded automatically" >&2
    exit 1
  done
  exit 0
fi

if [ "$(id -u)" = 0 ]; then
  chown -R postgres:postgres .
  exec gosu postgres sh "$0"
fi

# Retry after a failed run: drop the half-built cluster and undo pg_upgrade's
# link-mode marker, which is safe while the new cluster has never started.
rm -rf 19/upgrade
if [ -f 18/docker/global/pg_control.old ] && [ ! -f 18/docker/global/pg_control ]; then
  mv 18/docker/global/pg_control.old 18/docker/global/pg_control
fi
# After an unclean stop the lock names PID 1, which here is this shell, so
# PostgreSQL would refuse to start. Single-user mode then does crash recovery.
rm -f 18/docker/postmaster.pid

# Single-user mode runs as the bootstrap superuser, so no role name or password
# is needed. pg_upgrade records the upgrader's libc collation versions; c keeps
# the old ones, which describe how the indexes were built (NULL for musl).
out=$("$PGBINOLD/postgres" --single -D 18/docker -j template1 <<'SQL'
select concat_ws('|', pg_encoding_to_char(d.encoding), d.datlocprovider::text, d.datcollate,
    d.datctype, coalesce(d.datlocale, ''), current_setting('data_checksums'),
    pg_size_bytes(current_setting('wal_segment_size')) / 1048576, a.rolname) as r,
  (select 'update pg_database d set datcollversion = v.c from (values ' ||
    string_agg(format('(%L, %L::text)', datname, datcollversion), ', ') ||
    ') v(n, c) where d.datname = v.n' from pg_database) as c
  from pg_authid a, pg_database d where a.oid = 10 and d.datname = 'template0'
SQL
)
col() { printf '%s\n' "$out" | sed -n "s/^[[:space:]]*$1 = \"\(.*\)\"[[:space:]].*/\1/p"; }
r=$(col '1: r') collv=$(col '2: c')
[ -n "$r" ] && [ -n "$collv" ] || { echo "cannot read the PostgreSQL 18 cluster in 18/docker, see the errors above" >&2; exit 1; }
# The role name goes last: read leaves any '|' in it to the last variable.
IFS='|' read -r enc prov coll ctype loc sums wal user <<EOF
$r
EOF

set -- --username="$user" --encoding="$enc" --lc-collate="$coll" --lc-ctype="$ctype" --wal-segsize="$wal"
case $prov in
  i) set -- "$@" --locale-provider=icu --icu-locale="$loc" ;;
  b) set -- "$@" --locale-provider=builtin --builtin-locale="$loc" ;;
esac
[ "$sums" = on ] || set -- "$@" --no-data-checksums

mkdir -p 19
"$PGBINNEW/initdb" -D 19/upgrade "$@"
# pg_upgrade connects over a private socket; an old pg_hba.conf that asks for a
# password there (initdb --auth-local) would fail it.
hba=$(mktemp)
echo 'local all all trust' > "$hba"
"$PGBINNEW/pg_upgrade" --link -U "$user" -b "$PGBINOLD" -B "$PGBINNEW" -d 18/docker -D 19/upgrade \
  -o "-c hba_file=$hba" -O "-c hba_file=$hba"
printf '%s\n' "$collv" | "$PGBINNEW/postgres" --single -c exit_on_error=on -D 19/upgrade -j template1 >/dev/null
cp 18/docker/pg_hba.conf 18/docker/pg_ident.conf 18/docker/postgresql.auto.conf 19/upgrade/
mv -T 19/upgrade 19/docker
rm -f delete_old_cluster.sh "$hba"
echo "upgraded 18/docker to 19/docker; remove 18 once PostgreSQL 19 runs"
