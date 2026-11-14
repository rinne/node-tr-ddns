# DNS behaviour

`tr-ddns` is an authoritative name server for the domains added to it. It
is not a resolver: it never looks anything up elsewhere.

The examples assume a server that listens on `127.0.0.1` port 5300 and
has the domain and the hosts of the examples in [api.md](api.md). They
are run by the test suite.

```bash
dig @127.0.0.1 -p 5300 www.example.com A
dig @127.0.0.1 -p 5300 +tcp example.com MX
```

## What is answered

| Query | Answer |
| --- | --- |
| A name with records of the type asked | The records. |
| A name that exists but has no records of the type asked, whatever the type is | No records, with the SOA record of the domain in the authority section. |
| A name in a served domain that does not exist | NXDOMAIN, with the SOA record in the authority section. |
| A name with a CNAME record | The CNAME record, followed by the records of the target if the target is in a served domain too. |
| A name that is delegated, or is below a delegated name | A referral: the NS records of the delegation in the authority section and the addresses of those name servers, when known, in the additional section. |
| A name outside the served domains | Nothing at all. With `--dns-refuse-out-of-zone`, REFUSED. |

```bash
dig @127.0.0.1 -p 5300 example.com SOA
dig @127.0.0.1 -p 5300 www.example.com MX  # NODATA
dig @127.0.0.1 -p 5300 nothing.example.com A  # NXDOMAIN
dig @127.0.0.1 -p 5300 www.example.edu A  # no answer
```

A name exists when it is the top of a served domain, when it is a host,
or when there is a host below it: with a host `a.b.example.com`, the
name `b.example.com` exists and has no records.

Every answer has the AA flag set, except a referral and REFUSED. The RD
flag is copied from the query and RA is never set.

Names are not case sensitive. A name in a served domain that is not a
valid host name, for example one with an underscore in the middle of a
label, gets NXDOMAIN.

## What is ignored

The server does not respond at all to

- names outside the served domains (unless `--dns-refuse-out-of-zone`),
- packets that are not queries: responses, and operations other than a
  standard query such as UPDATE and NOTIFY,
- packets that do not have exactly one question,
- queries in a class other than IN,
- packets that cannot be parsed,
- sources that are over the rate limit.

Over TCP the connection is closed instead.

Staying silent gives nothing to someone who probes the server or tries
to use it to send traffic to a third party. The cost is that a resolver
that asks for a name the server does not serve waits for a timeout, which
only happens when a delegation points to the server by mistake.

## Record types

A host can have A, AAAA, TXT, MX, CNAME, NS, SRV and CAA records; see
[api.md](api.md#record-types) for the values. The top of every served
domain also has an SOA record and NS records, made from the settings of
the domain.

- **TXT.** A value longer than 255 bytes is sent as several character
  strings in one record, as DKIM keys need.
- **MX.** A value without a priority gets its position among the MX
  values of the host, starting from 1.
- **CNAME.** A name with a CNAME has no other records. A query for any
  other type gets the CNAME; if the target is in a served domain, its
  records of the type asked follow, through at most eight aliases.
- **NS on a host.** Delegates the host and everything below it to other
  name servers. Records at or below the delegated name are not served.
  A DS query for the delegated name itself is answered with no data,
  because the server does not sign.

Not supported: DNSSEC, zone transfers (AXFR, IXFR), dynamic update
(RFC 2136), wildcards, and other record types.

## SOA, NS and time to live

The settings of a domain decide these; see
[api.md](api.md#domain).

| Setting | Effect | Default |
| --- | --- | --- |
| `ns` | The NS records of the domain. The first one is the primary server in the SOA record. | the domain itself |
| `admin` | The administrator in the SOA record. | `postmaster` at the domain |
| `ttl` | The time to live of every record of the domain. | 60 |
| `refresh`, `retry`, `expiration` | The SOA timers. They matter only to secondary servers, which this server does not feed. | 300, 3, 10 |
| `minimum` | The SOA minimum. Resolvers remember a negative answer for the smaller of this and `ttl`. | 10 |

By default a domain is its own name server: its NS record is the domain
name. For that to resolve, give the domain an address
(`/host?host=example.com&a=...`), or set `ns` to the real names of the
servers. See [deployment.md](deployment.md).

The serial of the SOA record starts from the clock, grows by one with
every change in the domain, a host expiring included, and is saved in
the configuration file so that it does not go backwards over a restart.

The short default time to live suits records that change. The lifetime
of a host (`ttl` of the `/host` call) is a different thing: it is when
the host is removed from the server.

## Transport

- UDP and TCP, each on one or more addresses, IPv4 and IPv6.
- A client that sends an EDNS OPT record gets one back, and may get
  answers of up to the size it announced. The server offers 1232 bytes.
- An answer that does not fit is sent truncated (TC set, no records),
  and the client asks again over TCP. Without EDNS the limit is 512
  bytes.
- Several queries can be sent on one TCP connection. An idle connection
  is closed after ten seconds.

## Rate limiting

Each source address gets at most `--dns-rate-limit` queries answered per
second, 500 by default. The count starts over every second. All
addresses in one IPv6 /64 prefix count as one source. Queries over the
limit are ignored like any other unwanted packet, over UDP and TCP
alike, and counted in `dns.dropped.rateLimited` of `/stats`.

The default is far above what a resolver needs for a zone of dynamic
names, since resolvers cache. Lower it if the server is abused, raise it
or set it to 0 if a legitimate source hits it.
