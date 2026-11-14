# Configuration file

The configuration file holds everything the server serves: the domains,
their settings and the hosts. It is given with `-c` or `--config-file`.
There is nothing else in it; listen addresses, ports and the like are
command line options ([cli.md](cli.md)).

The server reads the file at startup and writes it when something
changes. It is not meant to be edited while the server runs: the next
write replaces the file with what the server has in memory. To change it
by hand, stop the server first. The usual way to change anything is the
[API](api.md).

## Running without one

With `--memory-only` in place of `--config-file` the server has no
configuration file. It starts with no domains and no hosts, keeps
everything in memory and saves nothing, so a restart starts from empty
again. This suits a server whose contents are set up by another program
every time it starts, for example with [`tr-ddns-ctl`](ctl.md) from the
startup of a container.

## Life cycle

1. `tr-ddns -c FILE --init-config-file` creates an empty file. It fails
   if the file exists.
2. At startup the file is read. If it is missing, unreadable or not a
   configuration, the server does not start.
3. Entries that cannot be used are skipped with a warning, and hosts
   whose lifetime has passed are dropped. The file is then rewritten in
   the current format, without what was skipped.
4. Every change through the API, and every host that expires, schedules
   a write. A change is written at once if the previous write is at
   least `--config-write-interval` seconds old (10 by default), and
   otherwise when that time is up, together with everything else that
   changed meanwhile.
5. On SIGTERM and SIGINT pending changes are written before the server
   exits. After a crash or a power failure, at most the changes of the
   last write interval are lost.

A write goes to a temporary file in the same directory, which then
replaces the old file in one step, so the file is always complete. The
directory must therefore be writable by the server. The permissions of
the file are kept, and if the file is a symbolic link, the file it
points to is replaced and the link stays.

If a write fails while the server runs, the server exits with status 1
rather than continue with changes it cannot keep.

## Format

A JSON object with two arrays.

```json
{
  "hosts": [
    {
      "name": "www.example.com",
      "lcname": "www.example.com",
      "domain": "example.com",
      "data": {
        "a": [ "192.0.2.10" ],
        "aaaa": [ "2001:db8:0:0:0:0:0:10" ],
        "txt": [],
        "mx": [],
        "cname": [],
        "ns": [],
        "srv": [],
        "caa": []
      },
      "expires": null
    }
  ],
  "domains": [
    {
      "name": "example.com",
      "lcname": "example.com",
      "serial": 3680022500,
      "expires": null,
      "ns": [ "ns1.example.com", "ns2.example.net" ],
      "admin": "hostmaster.example.com",
      "ttl": 300
    }
  ]
}
```

### Hosts

| Field | Meaning | When read |
| --- | --- | --- |
| `name` | The host name as it was given. | Required. |
| `data` | The records: for each record type an array of values in the form described in [api.md](api.md#record-types). | Required. A type may be missing. A single value may be a string instead of an array. |
| `expires` | When the host is removed, in milliseconds since the epoch, or `null` for never. | Optional. |
| `lcname` | The name in lower case. | Ignored; derived from `name`. |
| `domain` | The served domain the host is in. | Ignored; derived from `name`. |

### Domains

| Field | Meaning | When read |
| --- | --- | --- |
| `name` | The domain name as it was given. | Required. |
| `serial` | The SOA serial. | Optional. The serial continues from it unless the clock based serial is ahead. |
| `ns`, `admin`, `ttl`, `refresh`, `retry`, `expiration`, `minimum` | The settings of the domain; see [api.md](api.md#domain). Only the ones that differ from the defaults are written. | Optional. |
| `lcname` | The name in lower case. | Ignored. |
| `expires` | Always `null`. | Ignored. |

## Compatibility

Files written by every earlier version load.

- Before version 1.1.0 a record was a single string, not an array:
  `"data": { "a": "192.0.2.10" }`. This is still read.
- Files from before version 2.0.0 have only `a`, `aaaa`, `txt` and `mx`
  in `data` and no settings in the domains.

A file written by version 2.0.0 or later has the additional record types
in `data`, which versions before 2.0.0 ignore, so going back to an older
version loses only what the older version cannot serve.

## What is skipped at startup

Each of these is reported with a warning and left out:

- a domain whose name is not valid, or that is the same as, inside, or a
  parent of a domain earlier in the file,
- the settings of a domain if any of them is not valid; the domain is
  then served with the default settings,
- a host whose name is not valid or is not inside a served domain,
- a host with a value that is not valid for its record type, or with no
  `data`.

A host whose `expires` is in the past is dropped without a warning.
