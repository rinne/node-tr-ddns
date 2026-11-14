# TR-DDNS

## In A Nutshell

TR-DDNS is a small authoritative DNS server for names that change. Hosts
and their records are added, updated and removed through an HTTP API,
and are served right away. It is made for dynamic addresses, for
short-lived records such as ACME DNS-01 challenges, and for anything
else where editing a zone file is too slow.

- A, AAAA, TXT, MX, CNAME, NS, SRV and CAA records, several of each per
  host.
- Hosts can have a lifetime, after which they disappear on their own.
- DNS over UDP and TCP, IPv4 and IPv6.
- Everything is kept in one JSON file, or in memory only.
- Can run beside another server, for example in the same container,
  with only the DNS port exposed: it is then managed through a Unix
  socket with the `tr-ddns-ctl` command.
- Optional DNS over HTTP (RFC 8484) for a TLS reverse proxy in front.
- Can be used as a library.

It serves the domains it is given and nothing else: it is not a
resolver, and it does not do DNSSEC or zone transfers.

Requires Node.js 24 or newer.

## Installation

```
npm install -g tr-ddns
```

## Quick Start

Create an empty configuration file and start the server with DNS on port
5300 and the API on port 8080 of the local machine.

```
tr-ddns -c ddns.json --init-config-file
tr-ddns -c ddns.json --udp --tcp --udp-listen-port=5300 --tcp-listen-port=5300 --http-api --http-api-listen-address=127.0.0.1 --http-api-listen-port=8080
```

Add a domain and a host, and ask for it. These examples are run by the
test suite.

```bash
curl 'http://127.0.0.1:8080/domain?domain=example.com'
curl 'http://127.0.0.1:8080/host?host=www.example.com&a=192.0.2.10'
dig @127.0.0.1 -p 5300 www.example.com A
```

A record that removes itself after ten minutes:

```bash
curl 'http://127.0.0.1:8080/host?host=_acme-challenge.example.com&txt=some-token&ttl=600'
dig @127.0.0.1 -p 5300 _acme-challenge.example.com TXT
```

To serve a real domain, the server needs port 53 and a delegation from
the parent zone; see
[deployment](https://github.com/rinne/node-tr-ddns/blob/main/docs/deployment.md).

## Usage

```
Usage:
  tr-ddns [<opt> ...]
Options:
            --debug                          Enable debug messages
            --log-level=<arg>                Log level: none, error, warn, info or debug
  -c <arg>  --config-file=<arg>              Configuration file
            --init-config-file               Initialize configuration file and exit
            --memory-only                    Run without configuration file: start empty and save nothing
            --config-write-interval=<arg>    Shortest time in seconds between writes of configuration file
            --udp                            Enable UDP server
            --udp-listen-address=<arg>       Listen address(es) for UDP server, comma separated
            --udp-listen-port=<arg>          Listen port for UDP server
            --tcp                            Enable TCP server
            --tcp-listen-address=<arg>       Listen address(es) for TCP server, comma separated
            --tcp-listen-port=<arg>          Listen port for TCP server
            --dns-rate-limit=<arg>           Queries per second answered to one source, 0 for no limit
            --dns-refuse-out-of-zone         Answer REFUSED to queries outside of served domains instead of ignoring them
            --doh                            Enable DNS-over-HTTP server for a TLS proxy in front (plain HTTP, /dns-query)
            --doh-listen-address=<arg>       Listen address for DoH server
            --doh-listen-port=<arg>          Listen port for DoH server
            --doh-socket=<arg>               Unix domain socket for DoH server instead of address and port
            --doh-socket-mode=<arg>          Permissions of the DoH socket in octal
            --doh-trusted-proxy-hops=<arg>   Number of trusted proxies in front of DoH server adding X-Forwarded-For
            --http-api                       Enable HTTP-API server
            --http-api-user=<arg>            Required username for HTTP API server
            --http-api-password=<arg>        Required password for HTTP API server
            --http-api-password-file=<arg>   File containing required password for HTTP API server
            --http-api-listen-address=<arg>  Listen address for HTTP control server
            --http-api-listen-port=<arg>     Listen port for HTTP-API server
            --control-socket=<arg>           Serve the API also on this Unix domain socket
            --control-socket-mode=<arg>      Permissions of the control socket in octal
  -h        --help                           Show help and exit
Each option, except --config-file, --init-config-file and --help, can
also be given in environment variable TR_DDNS_OPT_<NAME>, where <NAME>
is the long option name in upper case with dashes as underscores, e.g.
TR_DDNS_OPT_UDP_LISTEN_PORT=5300. An option without an argument is
switched on with value true.
```

The API is open to everyone who can reach it unless a user and a
password are set. Let it listen on `127.0.0.1`, or protect it; see
[securing the API](https://github.com/rinne/node-tr-ddns/blob/main/docs/deployment.md#securing-the-api).

### Without a network API

With `--control-socket` the API is served on a Unix domain socket, and
`--http-api` can stay off. The `tr-ddns-ctl` command, which comes with
the package, talks to that socket:

```
tr-ddns -c ddns.json --udp --tcp --control-socket=/run/tr-ddns/control.sock

export TR_DDNS_OPT_CONTROL_SOCKET=/run/tr-ddns/control.sock
tr-ddns-ctl wait
tr-ddns-ctl domain ensure example.com
tr-ddns-ctl host set www.example.com a=192.0.2.10
tr-ddns-ctl host list
```

See [tr-ddns-ctl](https://github.com/rinne/node-tr-ddns/blob/main/docs/ctl.md)
and, for running inside a container next to a web server,
[deployment](https://github.com/rinne/node-tr-ddns/blob/main/docs/deployment.md#inside-a-container-with-a-web-server).

## API

All API methods work either with GET method and URL parameters or POST
method with JSON payload. Every response is JSON of the form
`{ "status": "ok", "code": 200, "data": ... }` or
`{ "status": "error", "code": 400, "message": "..." }`, and the HTTP
status is the same as `code`.

| Call | What it does |
| --- | --- |
| `/domain?domain=D` | Start serving a domain. Optional settings: `ns`, `admin`, `ttl`, `refresh`, `retry`, `expiration`, `minimum`. |
| `/domain?domain=D&update=true&...` | Change the settings of a served domain. |
| `/domain?domain=D&ensure=true` | Start serving a domain unless it is served already. For callers that run more than once. |
| `/domain?domain=D&remove=true` | Stop serving a domain and remove its hosts. |
| `/host?host=H&a=...&aaaa=...&txt=...` | Set the records of a host, replacing what it had. Record parameters: `a`, `aaaa`, `txt`, `mx`, `cname`, `ns`, `srv`, `caa`; repeat one for several values. |
| `/host?host=H&...&ttl=SECONDS` | The same, and remove the host after the given time. |
| `/host?host=H&...&merge=true` | Keep the records that the call does not mention. |
| `/host?host=H&remove=true` | Remove a host. |
| `/record?host=H&command=C&type=T&value=V` | `add`, `set`, `remove` or `clear` the values of one record type of a host. |
| `/dump` | All domains and hosts. |
| `/stats` | Counters. |
| `/flush` | Remove ALL hosts AND domains. |

```bash
curl 'http://127.0.0.1:8080/host?host=mail.example.com&a=192.0.2.25&a=192.0.2.26'
curl 'http://127.0.0.1:8080/host?host=example.com&mx=10+mail.example.com&txt=v%3Dspf1+mx+-all'
curl 'http://127.0.0.1:8080/host?host=www.example.com&aaaa=2001:db8::10&merge=true'
curl 'http://127.0.0.1:8080/record?host=www.example.com&command=add&type=a&value=192.0.2.11'
curl -H 'Content-Type: application/json' -d '{"host":"alias.example.com","cname":"www.example.com"}' 'http://127.0.0.1:8080/host'
curl 'http://127.0.0.1:8080/host?host=mail.example.com&remove=true'
```

Two things to keep in mind:

- `ttl` in a `host` call is the lifetime of the host, not the DNS time
  to live. It covers the whole host, and a later call without `ttl`
  makes the host permanent, also with `merge=true`.
- A `host` call without any record parameter removes the host.

## Documentation

- [Command line](https://github.com/rinne/node-tr-ddns/blob/main/docs/cli.md): options, environment variables, exit status, logging.
- [HTTP API](https://github.com/rinne/node-tr-ddns/blob/main/docs/api.md): every call, parameter and response.
- [tr-ddns-ctl](https://github.com/rinne/node-tr-ddns/blob/main/docs/ctl.md): managing a running server from the command line.
- [DNS behaviour](https://github.com/rinne/node-tr-ddns/blob/main/docs/dns.md): what is answered and what is ignored, record types, SOA and NS, rate limiting.
- [Configuration file](https://github.com/rinne/node-tr-ddns/blob/main/docs/config-file.md): format and how it is written.
- [Deployment](https://github.com/rinne/node-tr-ddns/blob/main/docs/deployment.md): delegation, port 53, securing the API, running as a service.
- [Library](https://github.com/rinne/node-tr-ddns/blob/main/docs/library.md): using the server from another program.
- [Upgrading](https://github.com/rinne/node-tr-ddns/blob/main/docs/upgrading.md): what changes when moving from 1.x or 2.x.
- [Changelog](https://github.com/rinne/node-tr-ddns/blob/main/CHANGELOG.md).

## Author

Timo J. Rinne <tri@iki.fi>


## License

MIT License
