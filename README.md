# TR-DDNS

## In A Nutshell

TR-DDNS is a simple dynamic-DNS server built on top of dns2 library.

## Usage

```
  tr-ddns [<opt> ...]

Options:
            --debug                          Enable debug messages
  -c <arg>  --config-file=<arg>              Configuration file
            --init-config-file               Initialize configuration file and exit
            --config-write-interval=<arg>    Shortest time in seconds between writes of configuration file
            --udp                            Enable UDP server
            --udp-listen-address=<arg>       Listen address(es) for UDP server, comma separated
            --udp-listen-port=<arg>          Listen port for UDP server
            --tcp                            Enable TCP server
            --tcp-listen-address=<arg>       Listen address(es) for TCP server, comma separated
            --tcp-listen-port=<arg>          Listen port for TCP server
            --dns-rate-limit=<arg>           Queries per second answered to one source, 0 for no limit
            --dns-refuse-out-of-zone         Answer REFUSED to queries outside of served domains instead of ignoring them
            --http-api                       Enable HTTP-API server
            --http-api-user=<arg>            Required username for HTTP API server
            --http-api-password=<arg>        Required passwordname for HTTP API server
            --http-api-password-file=<arg>   File containing required password for HTTP API server
            --http-api-listen-address=<arg>  Listen address for HTTP control server
            --http-api-listen-port=<arg>     Listen port for HTTP-API server
  -h        --help                           Show help and exit
```

Each option, except `--config-file`, `--init-config-file` and `--help`,
can also be given in environment variable `TR_DDNS_OPT_<NAME>`, where
`<NAME>` is the long option name in upper case with dashes as
underscores, for example `TR_DDNS_OPT_UDP_LISTEN_PORT=5353`. An option
without an argument is switched on with value `true`.

### Configuration file

All domains and hosts are kept in the configuration file, which the
server reads at startup and rewrites when something changes. Changes
that come in quick succession are written together: there is at least
`--config-write-interval` seconds (10 by default) between two writes.
The file is replaced in one step, so a crash cannot leave half a file
behind. On SIGTERM and SIGINT the pending changes are written before the
server exits.

### Securing the API

Without `--http-api-user`, anyone who can reach the API port can change
and remove everything, and the default listen address is `0.0.0.0`. The
server prints a warning at startup in that case. Either set a user and a
password, or let the API listen on `127.0.0.1` only. A password given on
the command line is visible in the process list;
`--http-api-password-file` reads it from the first line of a file
instead.

### What the DNS server answers

The server is authoritative for the domains it serves and answers
nothing else.

- A name that has records of the type asked: the records, with the AA
  flag set.
- A name that exists but has no records of the type asked, whatever the
  type is: an empty answer with the SOA record of the domain in the
  authority section.
- A name that does not exist in a served domain: NXDOMAIN, also with the
  SOA record.
- A name that has a CNAME record: the CNAME, followed by the records of
  the target if the target is served here as well.
- A name that is delegated with NS records, and every name below it: a
  referral to those name servers.
- A name outside the served domains: no answer at all, or REFUSED with
  `--dns-refuse-out-of-zone`.
- Anything that is not a plain query with one question: no answer.

Answers that do not fit in a UDP packet are truncated, and the client
retries over TCP, so enable both `--udp` and `--tcp`. The listen address
options take several addresses separated by commas, for example
`--udp-listen-address=0.0.0.0,::`.

### Rate limiting

A single source address (a /64 prefix for IPv6) gets at most
`--dns-rate-limit` queries answered per second, 500 by default. Queries
over the limit are ignored. `--dns-rate-limit=0` removes the limit.

## API

All API methods work either with GET method and URL parameters or POST
method with JSON payload. Every response is JSON of the form
`{ "status": "ok", "code": 200, "data": ... }` or
`{ "status": "error", "code": 400, "message": "..." }`, and the HTTP
status is the same as `code`.

If `--http-api-user` and a password are given, every call needs HTTP
Basic authentication (`curl -u user:password ...`).

### Add Domain

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld'
```

Fails if the domain already exists or if there is already a domain,
which is either a parent domain or a subdomain of the domain that is
added.

A domain has settings that can be given when it is added:

| Parameter | Meaning | Default |
| --- | --- | --- |
| `ns` | Name servers of the domain; repeat the parameter for several. The first one is the primary server in the SOA record. | the domain itself |
| `admin` | Mail address of the administrator, as `user@example.com` or in the SOA form `user.example.com` | `postmaster` at the domain |
| `ttl` | Time to live of the records of the domain, in seconds | 60 |
| `refresh`, `retry`, `expiration`, `minimum` | The timers of the SOA record, in seconds | 300, 3, 10, 10 |

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&ns=ns1.test-domain.tld&ns=ns2.test-domain.tld&admin=hostmaster@test-domain.tld&ttl=300'
```

By default the domain is its own name server, so for the delegation from
the parent zone to work, either give the domain an A or AAAA record
(`/host?host=test-domain.tld&a=...`) or set `ns` to the real names of the
servers. `minimum` is also how long resolvers remember that a name does
not exist.

### Change the Settings of a Domain

With `update=true` the call changes the settings of a domain that is
already served. Only the settings given are changed, and an empty value
brings back the default.

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&update=true&ttl=120'
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&update=true&ns='
```

### Remove Domain

Removes also all host records under that domain.

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&remove=true'
```

### Add or Update Host

A record parameter can be repeated (or be an array in a JSON payload) to
set several values of the same type. The supported records are

| Parameter | Value | Example |
| --- | --- | --- |
| `a` | IPv4 address | `1.2.3.4` |
| `aaaa` | IPv6 address | `2001:db8::1` |
| `txt` | Text, at most 4096 bytes | `v=spf1 -all` |
| `mx` | Mail server, optionally with a priority in front. Without one, the priority is the position of the value, starting from 1. | `10 mail.example.com` |
| `cname` | Target of an alias. A host that has a CNAME has no other records, and the top of a domain cannot have one. | `www.example.com` |
| `ns` | Name server that the host and everything under it is delegated to. Not for the top of a domain; use the `ns` setting of the domain. | `ns1.example.net` |
| `srv` | `priority weight port target` | `10 5 5060 sip.example.com` |
| `caa` | `flags tag value` | `0 issue letsencrypt.org` |

A host name consists of labels of letters, digits and hyphens. A label
may start with an underscore (`_acme-challenge`, `selector._domainkey`,
`_sip._tcp`), and the name may end with a dot.

```
curl 'http://TR-DDNS-ADDR/host?host=host1.test-domain.tld&a=1.2.3.4'
curl 'http://TR-DDNS-ADDR/host?host=host1.test-domain.tld&a=1.2.3.4&a=5.6.7.8'
curl 'http://TR-DDNS-ADDR/host?host=host2.test-domain.tld&a=1.2.3.4&aaaa=2001:db8::dead:beef&mx=my.mail.server.tld'
curl 'http://TR-DDNS-ADDR/host?host=_sometext.test-domain.tld&txt=this-is-probably-some-dynamic-authorization'
```

Lifetime can be set by ttl parameter, which makes the record disappear
after the given number of seconds. Lifetime is common for entire host,
so all records of the host are deleted, when the expiration occurs.

```
curl 'http://TR-DDNS-ADDR/host?host=_hello.test-domain.tld&txt=hello&ttl=3600'
```

All records for a host can be set with a single call and the
subsequent call replace all records of the host and remove previously
set records that are not present in the call. This behavior can be
overridden by using parameter `merge=true`, which causes the new
records to be merge on top of the old ones and spares the old records
that are not present in the call. Mostly this does what you'd expect,
but a couple things to keep in mind.

- Merge does not spare earlier TTL. If you want one, you'll have to submit
  it in all `host` calls and if you omit it, also the previously set
  records become non-expiring.
- Removing an existing record is done by setting it to an empty string.
  This DOES NOT actually set it to an empty string, but removes it.
  If the record is not present at all in the merge call, then the possible
  old record is left as it is.

### Remove Host

```
curl 'http://TR-DDNS-ADDR/host?host=_hello.test-domain.tld&remove=true'
```

A `host` call without any record parameter removes the host as well.

### Add, Set, Remove or Clear a Single Record

A host can have several records of each type. The `record` call changes
one type of one host and leaves the rest, including the lifetime of the
host, as it is. `command` is `add`, `set` (replace all values of the
type with this one), `remove` or `clear` (remove all values of the type;
no `value` needed). `type` is one of the record types above.

```
curl 'http://TR-DDNS-ADDR/record?host=host1.test-domain.tld&command=add&type=a&value=5.6.7.8'
curl 'http://TR-DDNS-ADDR/record?host=host1.test-domain.tld&command=remove&type=a&value=1.2.3.4'
curl 'http://TR-DDNS-ADDR/record?host=host1.test-domain.tld&command=clear&type=txt'
```

### Dump, Stats and Flush

```
curl 'http://TR-DDNS-ADDR/dump'
curl 'http://TR-DDNS-ADDR/stats'
curl 'http://TR-DDNS-ADDR/flush'
```

`dump` returns all domains and hosts, `stats` returns counters, and
`flush` removes ALL hosts AND domains.

## Author

Timo J. Rinne <tri@iki.fi>


## License

MIT License
