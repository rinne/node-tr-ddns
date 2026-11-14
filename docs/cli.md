# Command line

`tr-ddns` is the server program. Installing the package provides the
command; in a checkout of the repository it is `bin/tr-ddns`. The path
`./tr-ddns` at the top of the package, which was the program before
version 2.0.0, still starts it.

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

## Options

### General

| Option | Meaning | Default |
| --- | --- | --- |
| `-c <file>`, `--config-file=<file>` | The file that holds the domains and hosts. Required unless `--memory-only` is given. See [config-file.md](config-file.md). | |
| `--init-config-file` | Create an empty configuration file and exit. Fails if the file exists. | |
| `--memory-only` | Run without a configuration file: start with no domains and hosts, and save nothing. Everything is lost when the program stops. Cannot be combined with `--config-file`. | |
| `--config-write-interval=<seconds>` | The shortest time between two writes of the configuration file, 0 to 86400. Changes made sooner are written together when the time is up. | 10 |
| `--log-level=<level>` | `none`, `error`, `warn`, `info` or `debug`. | `info` |
| `--debug` | The same as `--log-level=debug`. | |
| `-h`, `--help` | Print the options and exit. | |

### DNS server

| Option | Meaning | Default |
| --- | --- | --- |
| `--udp` | Serve DNS over UDP. | off |
| `--udp-listen-address=<addresses>` | One address or several separated by commas, IPv4 or IPv6. | `0.0.0.0` |
| `--udp-listen-port=<port>` | | 53 |
| `--tcp` | Serve DNS over TCP. | off |
| `--tcp-listen-address=<addresses>` | One address or several separated by commas, IPv4 or IPv6. | `0.0.0.0` |
| `--tcp-listen-port=<port>` | | 53 |
| `--dns-rate-limit=<n>` | Queries per second answered to one source, 0 to 1000000; 0 means no limit. See [dns.md](dns.md#rate-limiting). | 500 |
| `--dns-refuse-out-of-zone` | Answer REFUSED to queries for names outside the served domains instead of ignoring them. | off |

Enable both `--udp` and `--tcp`: an answer that does not fit in a UDP
packet is truncated, and the client then asks again over TCP.

Whether `::` also accepts IPv4 depends on the operating system. Where it
does, which is the default on Linux, `--udp-listen-address=::` alone
serves both, and `0.0.0.0,::` together fails because the port is taken
twice.

### DNS over HTTP

| Option | Meaning | Default |
| --- | --- | --- |
| `--doh` | Serve DNS over HTTP (RFC 8484) at `/dns-query`, in plain HTTP for a reverse proxy that does TLS. See [dns.md](dns.md#dns-over-http). | off |
| `--doh-listen-address=<address>` | | `127.0.0.1` |
| `--doh-listen-port=<port>` | | 8053 |
| `--doh-socket=<path>` | Listen on a Unix domain socket instead of an address and a port. | |
| `--doh-socket-mode=<mode>` | The permissions of that socket file in octal. | `666` |
| `--doh-trusted-proxy-hops=<n>` | How many proxies in front add the address of their client to `X-Forwarded-For` and are trusted to do so, 0 to 32. | 0 |

This listener serves `/dns-query` and nothing else: the API is never
reachable through it. It does not need `--udp` or `--tcp`.

`--doh-trusted-proxy-hops` decides which address a query is counted
under for the rate limit. It must match the number of proxies that are
really in front: with 0 the address is that of the connection, which
behind a proxy is the proxy; with a number that is too high a client can
choose its own address.

### HTTP API

| Option | Meaning | Default |
| --- | --- | --- |
| `--http-api` | Serve the HTTP API. See [api.md](api.md). | off |
| `--http-api-listen-address=<address>` | | `0.0.0.0` |
| `--http-api-listen-port=<port>` | | 80 |
| `--http-api-user=<user>` | Require HTTP Basic authentication with this user name. Needs a password. | |
| `--http-api-password=<password>` | The password. Visible in the process list; prefer the file or the environment. | |
| `--http-api-password-file=<file>` | Read the password from the first line of a file. Cannot be combined with `--http-api-password`. | |

### Control socket

| Option | Meaning | Default |
| --- | --- | --- |
| `--control-socket=<path>` | Serve the API also on a Unix domain socket at this path. | off |
| `--control-socket-mode=<mode>` | The permissions of the socket file in octal. | `600` |

The control socket is the API of [api.md](api.md) without a network port
and without authentication: whoever may open the socket file may do
everything. It does not need `--http-api`, and when nothing but DNS
should be reachable from outside, it is the way to manage the server.
[`tr-ddns-ctl`](ctl.md) talks to it, and so does any HTTP client that
can use a Unix socket:

```
curl --unix-socket /run/tr-ddns/control.sock 'http://localhost/stats'
```

Keep the socket in a directory that only the intended users can enter.
Unix domain sockets are for Linux, macOS and other Unix systems.

The socket file is created at startup and removed at exit. A socket file
left behind by a server that was killed is replaced; a socket that
another server is listening on, or a file that is not a socket, stops
the program. The directory must exist and be writable by the server.

Without a user and a password the API is open to everyone who can reach
the port. The program warns about it at startup unless the listen
address is a loopback address.

## Environment variables

Each option, except `--config-file`, `--init-config-file` and `--help`,
can also be given in an environment variable. The name is
`TR_DDNS_OPT_` followed by the long option name in upper case with
dashes as underscores. An option without an argument is switched on with
the value `true`. An option on the command line wins over the
environment.

| Variable | Option |
| --- | --- |
| `TR_DDNS_OPT_DEBUG` | `--debug` |
| `TR_DDNS_OPT_LOG_LEVEL` | `--log-level` |
| `TR_DDNS_OPT_CONFIG_WRITE_INTERVAL` | `--config-write-interval` |
| `TR_DDNS_OPT_MEMORY_ONLY` | `--memory-only` |
| `TR_DDNS_OPT_UDP` | `--udp` |
| `TR_DDNS_OPT_UDP_LISTEN_ADDRESS` | `--udp-listen-address` |
| `TR_DDNS_OPT_UDP_LISTEN_PORT` | `--udp-listen-port` |
| `TR_DDNS_OPT_TCP` | `--tcp` |
| `TR_DDNS_OPT_TCP_LISTEN_ADDRESS` | `--tcp-listen-address` |
| `TR_DDNS_OPT_TCP_LISTEN_PORT` | `--tcp-listen-port` |
| `TR_DDNS_OPT_DNS_RATE_LIMIT` | `--dns-rate-limit` |
| `TR_DDNS_OPT_DNS_REFUSE_OUT_OF_ZONE` | `--dns-refuse-out-of-zone` |
| `TR_DDNS_OPT_DOH` | `--doh` |
| `TR_DDNS_OPT_DOH_LISTEN_ADDRESS` | `--doh-listen-address` |
| `TR_DDNS_OPT_DOH_LISTEN_PORT` | `--doh-listen-port` |
| `TR_DDNS_OPT_DOH_SOCKET` | `--doh-socket` |
| `TR_DDNS_OPT_DOH_SOCKET_MODE` | `--doh-socket-mode` |
| `TR_DDNS_OPT_DOH_TRUSTED_PROXY_HOPS` | `--doh-trusted-proxy-hops` |
| `TR_DDNS_OPT_HTTP_API` | `--http-api` |
| `TR_DDNS_OPT_HTTP_API_USER` | `--http-api-user` |
| `TR_DDNS_OPT_HTTP_API_PASSWORD` | `--http-api-password` |
| `TR_DDNS_OPT_HTTP_API_PASSWORD_FILE` | `--http-api-password-file` |
| `TR_DDNS_OPT_HTTP_API_LISTEN_ADDRESS` | `--http-api-listen-address` |
| `TR_DDNS_OPT_HTTP_API_LISTEN_PORT` | `--http-api-listen-port` |
| `TR_DDNS_OPT_CONTROL_SOCKET` | `--control-socket` |
| `TR_DDNS_OPT_CONTROL_SOCKET_MODE` | `--control-socket-mode` |

## Starting and stopping

With `--memory-only` there is nothing to prepare. Otherwise the
configuration file must exist. Create it once:

```
tr-ddns -c /var/lib/tr-ddns/config.json --init-config-file
```

Then start the server:

```
tr-ddns -c /var/lib/tr-ddns/config.json --udp --tcp --http-api --http-api-listen-address=127.0.0.1 --http-api-listen-port=8080
```

On SIGTERM and SIGINT the program writes pending changes to the
configuration file, closes its listeners and exits with status 0.

## Exit status

| Status | When |
| --- | --- |
| 0 | After `--help`, after `--init-config-file`, and after SIGTERM or SIGINT. |
| 1 | An invalid option; a configuration file that is missing, unreadable or malformed; `--init-config-file` when the file exists; a password file that cannot be used; a listener that cannot be started; a configuration file that cannot be written. |

A message on the standard error tells which.

## Logging

Messages are printed with a time stamp in UTC. Errors and warnings go to
the standard error, the rest to the standard output.

| Level | What is printed |
| --- | --- |
| `error` | Failures inside API calls. |
| `warn` | Also entries of the configuration file that were skipped at startup, and the warning about an API without authentication. |
| `info` | Also a line for every write of the configuration file. |
| `debug` | Also every DNS query and response, every change in the database, and details of rejected input. |

Messages about a failure that ends the program are printed at every
level.
