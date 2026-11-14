# Upgrading from 1.x to 2.0

Version 2.0.0 keeps the command line, the API calls, the configuration
file and the library interface of 1.1.1. A 1.1.1 command line, a 1.1.1
configuration file and a 1.1.1 API client work as they are. What does
change is listed here; [CHANGELOG.md](../CHANGELOG.md) has the complete
list with the additions.

## Before upgrading

- **Node.js 24 or newer is required.**
- The server now writes the configuration file through a temporary file
  in the same directory. The user that runs the server needs write
  access to the **directory**, not only to the file.
- Keep a copy of the configuration file. Version 2.0 reads files written
  by 1.x, and 1.x reads files written by 2.0 but ignores the record
  types and domain settings it does not know.

## What a DNS client sees

These bring the server in line with what resolvers expect from an
authoritative server.

| | 1.1.1 | 2.0.0 |
| --- | --- | --- |
| AA flag | Not set. | Set on every answer, except a referral. |
| A name in a served domain that does not exist | Empty answer, NOERROR. | NXDOMAIN. |
| Answers without data | Nothing in the authority section. | The SOA record of the domain in the authority section. |
| A query type the server has no data for, such as HTTPS (65) | No response; the client waits for a timeout. | An empty answer. |
| A name in a served domain that is not a valid host name | No response. | NXDOMAIN. |
| MX | Never answered, because of a defect. | Answered. |
| A TXT value longer than 255 bytes | A malformed response. | One record with several strings. |
| A client using EDNS | No OPT record in the answer. | An OPT record in the answer. |
| Packets that are not plain queries (responses, UPDATE, NOTIFY, several questions) | Processed as queries. | Ignored. |
| Queries from one source | Unlimited. | 500 per second answered, the rest ignored. Change with `--dns-rate-limit`; 0 removes the limit. |

Unchanged: a query for a name outside the served domains gets no
response at all, unless the new `--dns-refuse-out-of-zone` is given.

If a resolver has cached "no such name" for a name, it now really is
cached, for the SOA minimum of the domain (10 seconds by default). A
host added right after a failed lookup can take that long to appear.

## What an API client sees

| | 1.1.1 | 2.0.0 |
| --- | --- | --- |
| Errors from the HTTP layer: unsupported method, unreadable body, body read timeout | `text/plain`. | JSON in the usual envelope: `{ "status": "error", "code": ..., "message": ... }`. |
| A path with an empty or dot segment, such as `//host` | 404. | 400. |
| A request body over 64 KiB | Accepted. | 413. |
| A JSON body that is an array, or has a key `__proto__`, `constructor` or `prototype` | Accepted. | 400. |
| `/record` with an invalid value | 400, but the host was rewritten and lost its lifetime. | 400, nothing changes. |
| `/record` on a host with a lifetime | The host became permanent. | The lifetime is kept. |
| `/host` with `merge=true` on a host with TXT and MX records | TXT values were copied into MX. | MX is left alone. |
| `/host` with `remove=true` and `mx` | Accepted. | 400, as with the other record types. |
| `ttl` (lifetime) over about 24.8 days | 400. | Accepted. |
| A repeated record parameter (`a=...&a=...`) | An error. | Sets several values. |
| An IPv4 address in a short form such as `10.1` | Stored as given. | Stored as `10.0.0.1`. |
| An MX host | Stored as given. | Stored in lower case. |
| A TXT value over 4096 bytes, or more than 100 values of a type | Accepted. | 400. |
| `/dump` | `data` of a host has `a`, `aaaa`, `txt`, `mx`. | Also `cname`, `ns`, `srv`, `caa`, empty when unused. Domains may have settings. |
| `/stats` | | Also `authFailures` and `dns`. |

Responses to successful calls and the messages of the 400 errors are the
same as before.

## What the operator sees

- **A listener that cannot be started ends the program** with status 1
  and a message. In 1.1.1 a DNS port that was in use was silently
  ignored and the program kept running without DNS.
- **SIGTERM and SIGINT** write pending changes to the configuration file
  and exit with status 0. In 1.1.1 the program was killed by the signal
  and up to ten seconds of changes were lost.
- **A missing configuration file** is reported as missing, with a hint
  to use `--init-config-file`. In 1.1.1 the message said that the
  configuration was malformed.
- **Entries with invalid record values in the configuration file** are
  skipped with a warning at startup. In 1.1.1 values in arrays were not
  checked.
- **A warning at startup** when the API listens on an address other than
  loopback without authentication. The defaults are unchanged.
- **Less output.** The whole database is no longer printed on every
  write of the configuration file, and queries that get no answer are
  logged only with `--debug`. Usage errors of the command line go to the
  standard error. `--log-level` selects what is printed.
- **The program moved** to `bin/tr-ddns`, and installing the package now
  provides the `tr-ddns` command. The old path `tr-ddns` at the top of
  the package still works.

## What a program using the library sees

- `require('tr-ddns')` and `require('tr-ddns/namedb')`,
  `/nameserver`, `/apiserver`, `/log`, `/nullish` and `/ts` work as
  before. Other files of the package can no longer be required.
- `NameServer` and `ApiServer` emit `error` when a listener cannot be
  started. As with any `EventEmitter`, an `error` event without a
  handler is thrown. `ApiServer` used to end the process itself, and
  `NameServer` used to say nothing.
- `NameServer` limits queries to 500 per second per source unless
  `rateLimit` says otherwise.
- `NameDB.get()` returns an empty array for every type it has no data
  for, where it returned `false` for types it did not know. Its `data`
  for a TXT value over 255 bytes is an array of buffers.
- `NameDB.set()` validates every value, also in arrays and sets, and
  copies a `Set` it is given instead of keeping it.
- `NameDB.dump()` has the additional record types in `data`.
- A `NameDB` keeps the process alive with its timers, as before; the
  new `close()` stops them.
- Creating a component with `debug: true` sets the log level of the
  process to `debug`.
