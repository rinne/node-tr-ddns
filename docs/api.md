# HTTP API

The API is how domains and hosts are added, changed and removed. It is
enabled with `--http-api`; see [cli.md](cli.md) for the listen address,
the port and authentication. The same API is served on a Unix domain
socket with `--control-socket`, which is what
[`tr-ddns-ctl`](ctl.md) uses.

The examples below assume a server whose API listens on
`127.0.0.1:8080`. They are run by the test suite, in the order they
appear.

## Requests

Every call works in two ways:

- GET with the parameters in the query string.
- POST with the parameters as a JSON object in the body
  (`Content-Type: application/json`), or form encoded
  (`application/x-www-form-urlencoded`).

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.com'
curl -H 'Content-Type: application/json' -d '{"host":"www.example.com","a":"192.0.2.10"}' 'http://127.0.0.1:8080/host'
```

PUT is handled like POST and DELETE like GET. A POST or PUT must not
have a query string, and a GET or DELETE must not have a body. A
parameter that takes several values is repeated in a query string and is
an array in JSON. `true` and `false` are given as those words in a query
string and as booleans or strings in JSON.

A request body is at most 64 KiB. A JSON body must be an object, and a
key named `__proto__`, `constructor` or `prototype` is refused.

## Responses

Every response is JSON, and the HTTP status is the same as `code`.

```json
{ "status": "ok", "code": 200 }
{ "status": "ok", "code": 200, "data": { } }
{ "status": "error", "code": 400, "message": "Bad request (host)" }
```

| Code | Meaning |
| --- | --- |
| 200 | Done. |
| 400 | Something in the request is wrong. The message names the parameter or the reason in parentheses. |
| 401 | Authentication is required and the credentials are missing or wrong. |
| 404 | No such call. |
| 405 | A method other than GET, POST, PUT and DELETE. |
| 408 | The request body did not arrive in five seconds. |
| 413 | The request body is too large. |
| 500 | An internal error. |

## Authentication

When the server is started with `--http-api-user` and a password, every
call needs HTTP Basic authentication.

```bash
curl -u admin:secret 'http://127.0.0.1:8080/'
```

Basic authentication sends the password in a form anyone on the path can
read. The API does not do TLS itself; see
[deployment.md](deployment.md#securing-the-api).

## `/`

Identifies the server.

```bash
curl 'http://127.0.0.1:8080/'
```

```json
{ "status": "ok", "code": 200, "data": { "package": "tr-ddns", "version": "2.0.0" } }
```

## `/domain`

Adds, changes or removes a served domain.

| Parameter | Meaning |
| --- | --- |
| `domain` | The domain. Required. |
| `remove` | `true` removes the domain and all of its hosts. |
| `update` | `true` changes the settings of a domain that is already served. |
| `ensure` | `true` adds the domain if it is not served; if it is, the call succeeds and applies the settings given. For callers that run more than once. |
| `ns` | Setting: name servers of the domain. Repeat for several. The first one is the primary server in the SOA record. Default: the domain itself. |
| `admin` | Setting: mail address of the administrator, as `user@example.com` or in the SOA form `user.example.com`. Default: `postmaster` at the domain. |
| `ttl` | Setting: time to live of the records of the domain in seconds. Default: 60. |
| `refresh`, `retry`, `expiration`, `minimum` | Settings: the timers of the SOA record in seconds. Defaults: 300, 3, 10, 10. `minimum` is also how long resolvers remember that a name does not exist. |

### Add a domain

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.net'
curl 'http://127.0.0.1:8080/domain?domain=example.org&ns=ns1.example.org&ns=ns2.example.org&admin=hostmaster@example.org&ttl=300'
```

Adding fails with 400 if the domain is served already, or if a served
domain is a parent or a subdomain of it.

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.com'  # 400: already served
curl 'http://127.0.0.1:8080/domain?domain=sub.example.com'  # 400: inside a served domain
```

With `ensure=true` the call says what should be there, and can be
repeated:

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.net&ensure=true'
curl 'http://127.0.0.1:8080/domain?domain=example.net&ensure=true&ttl=600'
```

### Change the settings

Only the settings given are changed. An empty value brings back the
default.

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.org&update=true&ttl=120&minimum=60'
curl 'http://127.0.0.1:8080/domain?domain=example.org&update=true&admin='
```

### Remove a domain

Removes the hosts of the domain as well. Removing a domain that is not
served is not an error.

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.net&remove=true'
```

## `/host`

Sets all records of a host, or removes the host.

| Parameter | Meaning |
| --- | --- |
| `host` | The host name. Required. It must be inside a served domain; the domain name itself is a valid host. |
| a record type | The values of that type; see below. Repeat for several values. An empty value means no values of that type. |
| `ttl` | Lifetime of the host in seconds. When it has passed, the host and all of its records are removed. Without it the host stays until it is removed. This is not the DNS time to live, which is a setting of the domain. |
| `merge` | `true` keeps the records that the call does not mention; see below. |
| `remove` | `true` removes the host. |
| `ensure` | With `remove=true`: `true` makes the call succeed also when there is no such host. |

### Record types

| Parameter | Value | Example |
| --- | --- | --- |
| `a` | IPv4 address | `192.0.2.10` |
| `aaaa` | IPv6 address | `2001:db8::10` |
| `txt` | Text, at most 4096 bytes | `v=spf1 -all` |
| `mx` | Mail server, optionally with a priority in front. Without one, the priority is the position of the value among the MX values of the host, starting from 1. | `10 mail.example.com` |
| `cname` | Target of an alias. One value only. A host that has a CNAME has no other records, and the top of a domain cannot have one. | `www.example.com` |
| `ns` | Name server that the host and everything under it is delegated to. Not for the top of a domain; use the `ns` setting of the domain. | `ns1.example.net` |
| `srv` | `priority weight port target` | `10 5 5060 sip.example.com` |
| `caa` | `flags tag value` | `0 issue letsencrypt.org` |

A host has at most 100 values of one type.

A host name consists of labels of letters, digits and hyphens separated
by dots. A label is at most 63 characters, does not start or end with a
hyphen, and may start with an underscore (`_acme-challenge`,
`selector._domainkey`, `_sip._tcp`). The whole name is at most 253
characters and may end with a dot. Names are not case sensitive.

### Set the records of a host

Without `merge`, the call replaces everything the host had.

```bash
curl 'http://127.0.0.1:8080/host?host=www.example.com&a=192.0.2.10&aaaa=2001:db8::10'
curl 'http://127.0.0.1:8080/host?host=example.com&a=192.0.2.10&a=192.0.2.11&mx=10+mail.example.com&txt=v%3Dspf1+mx+-all'
curl 'http://127.0.0.1:8080/host?host=_acme-challenge.example.com&txt=token-from-the-certificate-authority&ttl=3600'
curl 'http://127.0.0.1:8080/host?host=alias.example.com&cname=www.example.com'
curl 'http://127.0.0.1:8080/host?host=_sip._tcp.example.com&srv=10+5+5060+sip.example.com'
curl -H 'Content-Type: application/json' -d '{"host":"mail.example.com","a":["192.0.2.25","192.0.2.26"],"ttl":86400}' 'http://127.0.0.1:8080/host'
```

### Merge

With `merge=true` the call is laid on top of what the host has:

- A record type that is not in the call is left as it is.
- A single value is added to the values of its type.
- Several values of a type replace the values of that type.
- An empty value removes the values of that type.

```bash
curl 'http://127.0.0.1:8080/host?host=www.example.com&txt=hello&merge=true'
curl 'http://127.0.0.1:8080/host?host=www.example.com&aaaa=&merge=true'
```

Merge does not keep the lifetime. A call without `ttl` makes the host
permanent, also with `merge=true`; give `ttl` in every call to keep the
host expiring.

### Remove a host

```bash
curl 'http://127.0.0.1:8080/host?host=mail.example.com&remove=true'
```

A call that has no record parameter at all removes the host too.
Removing a host that does not exist fails with 400.

```bash
curl 'http://127.0.0.1:8080/host?host=alias.example.com'
curl 'http://127.0.0.1:8080/host?host=alias.example.com&remove=true'  # 400: no such host
curl 'http://127.0.0.1:8080/host?host=alias.example.com&remove=true&ensure=true'
```

## `/record`

Changes the values of one record type of one host and leaves everything
else, the lifetime of the host included, as it is. The host is created
if it does not exist.

| Parameter | Meaning |
| --- | --- |
| `host` | The host name. Required. |
| `type` | A record type from the table above. Required. |
| `command` | `add` adds the value. `set` replaces all values of the type with the value. `remove` removes the value. `clear` removes all values of the type. Required. |
| `value` | The value. Required except for `clear`. |

```bash
curl 'http://127.0.0.1:8080/record?host=www.example.com&command=add&type=a&value=192.0.2.12'
curl 'http://127.0.0.1:8080/record?host=www.example.com&command=remove&type=a&value=192.0.2.10'
curl 'http://127.0.0.1:8080/record?host=www.example.com&command=set&type=txt&value=only+this'
curl 'http://127.0.0.1:8080/record?host=www.example.com&command=clear&type=txt'
```

## `/dump`

Returns all domains and hosts in the form they have in the configuration
file; see [config-file.md](config-file.md).

```bash
curl 'http://127.0.0.1:8080/dump'
```

## `/stats`

Returns counters since the start of the server.

```bash
curl 'http://127.0.0.1:8080/stats'
```

```json
{
  "status": "ok",
  "code": 200,
  "data": {
    "lookup": { "total": 120, "errors": 3 },
    "domains": 2,
    "hosts": 5,
    "apiCalls": 42,
    "authFailures": 0,
    "dns": {
      "queries": 125,
      "answered": 117,
      "nxdomain": 4,
      "empty": 9,
      "refused": 0,
      "dropped": { "notQuery": 0, "invalid": 1, "outOfZone": 3, "rateLimited": 4, "error": 0 }
    }
  }
}
```

| Counter | Meaning |
| --- | --- |
| `lookup.total` | Lookups made in the database. |
| `lookup.errors` | Lookups for names outside the served domains. |
| `domains`, `hosts` | What is served right now. |
| `apiCalls` | API requests received. |
| `authFailures` | API requests refused with 401. |
| `dns.queries` | DNS packets received. |
| `dns.answered` | Queries answered. |
| `dns.nxdomain` | Of those, answers saying that the name does not exist. |
| `dns.empty` | Of those, answers saying that the name has no records of the type. |
| `dns.refused` | Queries answered with REFUSED (`--dns-refuse-out-of-zone`). |
| `dns.dropped.notQuery` | Ignored: not a plain query with one question. |
| `dns.dropped.invalid` | Ignored: unreadable, or a class other than IN. |
| `dns.dropped.outOfZone` | Ignored: a name outside the served domains. |
| `dns.dropped.rateLimited` | Ignored: the source was over its rate limit. |
| `dns.dropped.error` | Ignored: an internal error while answering. |

| `doh.requests` | HTTP requests received by the DNS over HTTP listener. |
| `doh.answered` | Of those, answered with a DNS response. |
| `doh.badRequest` | Refused: no usable query, a wrong method or content type, a body too large. |
| `doh.notFound` | Refused: a path other than `/dns-query`. |
| `doh.rateLimited` | Refused with 429: the source was over its rate limit. |
| `doh.errors` | Failed with 500. |

`dns` is present when DNS is served in any way, and counts queries from
all of them: UDP, TCP and HTTP. `doh` is present with `--doh`.

## `/flush`

Removes all hosts and all domains. There is no confirmation and no way
back.

```bash
curl 'http://127.0.0.1:8080/flush'
```
