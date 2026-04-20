# dtrace/

Example trace scripts for BIND 9's static user-space (USDT) probes.

## What's instrumented

BIND 9 ships USDT probes declared in three providers:

- `lib/dns/probes-dns.d` — provider `libdns` (`xfrin_*`, `delegdb_*`)
- `lib/ns/probes-ns.d`   — provider `libns`  (`rrl_*`)
- `lib/isc/probes-isc.d` — provider `libisc` (`rwlock_*`, `job_*`)

The probes compile to zero-cost nops when no consumer is attached, and
are only wired up when the build finds `dtrace` and `sys/sdt.h` (meson
option `-Dtracing=auto|enabled`, default `auto`).  With
`-Dtracing=disabled` the probe macros are stripped entirely.

## Listing available probes

On Linux (SystemTap / USDT):

    stap -l 'process("/path/to/named").mark("*")' | sort

On FreeBSD or macOS (DTrace):

    dtrace -l -n 'libdns*:::*'

## Scripts

| Script | Purpose |
|---|---|
| [`delegdb-trace.stp`](delegdb-trace.stp) | Streams every insertion, eviction, and `rndc flush-delegation` removal in the delegation cache. |

## Running a script

The scripts take the `named` binary path as their first positional
argument, so they work with either an installed or a freshly-built
named:

    sudo stap dtrace/delegdb-trace.stp /usr/sbin/named -x $(pidof named)
    sudo stap dtrace/delegdb-trace.stp build/named -c "build/named -g -f"

The `-c` form runs `named` under stap's supervision and exits with it.
