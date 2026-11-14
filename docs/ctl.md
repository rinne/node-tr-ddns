# tr-ddns-ctl

`tr-ddns-ctl` sends commands to a running `tr-ddns` through its control
socket. It is meant for the scripts and programs on the same machine
that are in charge of the server: no network port is involved and no
password is needed, because access is decided by the permissions of the
socket file.

The server must be started with `--control-socket`; see
[cli.md](cli.md#control-socket). The tool only talks to a running
server. It never reads or writes the configuration file.

```
Usage:
  tr-ddns-ctl [<opt> ...] [<param> ...]
Options:
  -s <arg>  --socket=<arg>     Control socket of the server
            --timeout=<arg>    Seconds to wait for the server
            --json             Print the response of the server as JSON
            --if-exists        With host remove: not an error if there is no such host
            --yes              Confirm flush
  -h        --help             Show help and exit
Commands:
  wait                                    Wait until the server answers
  info                                    Show the name and version of the server
  domain list                             List the served domains
  domain show <domain>                    Show a domain and its settings
  domain add <domain> [<setting>=<value> ...]
                                          Start serving a domain
  domain ensure <domain> [<setting>=<value> ...]
                                          The same, but fine if it is served already
  domain set <domain> <setting>=<value> ...
                                          Change settings of a served domain
  domain remove <domain>                  Stop serving a domain and remove its hosts
  host list [<domain>]                    List the hosts
  host show <host>                        Show the records of a host
  host set <host> <type>=<value> ... [ttl=<seconds>]
                                          Set the records of a host, replacing the old ones
  host merge <host> <type>=<value> ... [ttl=<seconds>]
                                          Set records of a host, keeping the other types
  host remove <host>                      Remove a host
  record add <host> <type> <value>        Add a value to the records of a type
  record set <host> <type> <value>        Replace the records of a type with a value
  record remove <host> <type> <value>     Remove a value
  record clear <host> <type>              Remove all records of a type
  dump                                    Print all domains and hosts as JSON
  stats                                   Print the counters as JSON
  flush                                   Remove ALL hosts AND domains; needs --yes
Settings: ns, admin, ttl, refresh, retry, expiration, minimum. Types: a, aaaa, txt, mx, cname, ns, srv, caa.
A setting or a type can be repeated to give it several values, and an
empty value resets a setting or, with merge, removes the records of a type.
Exit status: 0 done, 1 refused by the server, 2 invalid command line,
3 no answer from the server.
```

The options come before the command.

| Option | Meaning | Default |
| --- | --- | --- |
| `-s <path>`, `--socket=<path>` | The control socket of the server. Also read from `TR_DDNS_OPT_CONTROL_SOCKET`, the variable that gives the same path to the server. | |
| `--timeout=<seconds>` | How long to wait for an answer, and for `wait`, how long to keep trying. Also `TR_DDNS_OPT_CTL_TIMEOUT`. | 10 |
| `--json` | Print the response of the server, as described in [api.md](api.md#responses), on one line. | |
| `--if-exists` | With `host remove`: succeed if there is no such host. | |
| `--yes` | Needed by `flush`. | |

## Commands

The examples assume that `TR_DDNS_OPT_CONTROL_SOCKET` is set. They are
run by the test suite, in order.

### Waiting for the server

`wait` returns when the server answers, or fails with status 3 when the
time given with `--timeout` is up. A script that has just started the
server uses it before anything else.

```bash
tr-ddns-ctl --timeout=30 wait
tr-ddns-ctl info
```

### Domains

`domain add` fails if the domain is served already. `domain ensure` adds
the domain if it is not served and otherwise leaves it as it is, apart
from the settings given, which are applied. Use `ensure` in anything
that runs more than once, such as the startup of a container that keeps
its configuration file.

The settings are `ns`, `admin`, `ttl`, `refresh`, `retry`, `expiration`
and `minimum`; see [api.md](api.md#domain). `ns` can be repeated. An
empty value brings back the default.

```bash
tr-ddns-ctl domain ensure example.com
tr-ddns-ctl domain ensure example.com
tr-ddns-ctl domain add example.com  # exit 1: served already
tr-ddns-ctl domain ensure example.org ns=ns1.example.org ns=ns2.example.org admin=hostmaster@example.org ttl=300
tr-ddns-ctl domain set example.org ttl=120 admin=
tr-ddns-ctl domain list
tr-ddns-ctl domain show example.org
tr-ddns-ctl domain remove example.org
```

`domain remove` removes the hosts of the domain too, and succeeds also
when the domain is not served.

### Hosts

`host set` replaces all records of a host. `host merge` keeps the record
types that are not mentioned, adds a single value to the values of its
type, and replaces a type that is given several values; an empty value
removes the records of that type. The record types are those of
[api.md](api.md#record-types), and a type can be repeated.

`ttl` is the lifetime of the host in seconds. As in the API, a `set` or
`merge` without it makes the host permanent.

```bash
tr-ddns-ctl host set www.example.com a=192.0.2.10 a=192.0.2.11 aaaa=2001:db8::10
tr-ddns-ctl host set _acme-challenge.example.com txt=some-token ttl=600
tr-ddns-ctl host merge www.example.com txt=hello
tr-ddns-ctl host merge www.example.com aaaa=
tr-ddns-ctl host list
tr-ddns-ctl host list example.com
tr-ddns-ctl host show www.example.com
tr-ddns-ctl host remove _acme-challenge.example.com
tr-ddns-ctl host remove _acme-challenge.example.com  # exit 1: no such host
tr-ddns-ctl --if-exists host remove _acme-challenge.example.com
```

`host show` prints one line for each value, the record type first, and
an `expires` line with the time when the host has a lifetime:

```
a 192.0.2.10
a 192.0.2.11
txt hello
```

### Single records

These change the values of one record type and leave the rest of the
host, its lifetime included, as it is.

```bash
tr-ddns-ctl record add www.example.com a 192.0.2.12
tr-ddns-ctl record remove www.example.com a 192.0.2.10
tr-ddns-ctl record set www.example.com txt 'only this'
tr-ddns-ctl record clear www.example.com txt
```

### Everything at once

`dump` and `stats` print the data of the API calls of the same names as
JSON. `flush` removes all hosts and all domains and therefore needs
`--yes`.

```bash
tr-ddns-ctl dump
tr-ddns-ctl stats
tr-ddns-ctl flush  # exit 2: needs --yes
tr-ddns-ctl --yes flush
```

## Output

A command that changes something prints nothing when it succeeds. The
listing commands print one name on a line. Errors go to the standard
error with the message of the server:

```
tr-ddns-ctl: Bad request (unable to add domain)
```

With `--json` every command prints the response of the server instead.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | The server refused the command, or what was asked for does not exist. |
| 2 | The command line is not valid. Nothing was sent. |
| 3 | No answer from the server: no socket, nobody listening on it, or the time ran out. |

## In a startup script

Start the server, wait for it, and say what should be served. With
`ensure` the script can run on every start, whether the configuration
file is new or kept from before.

```
export TR_DDNS_OPT_CONTROL_SOCKET=/run/tr-ddns/control.sock

tr-ddns -c /var/lib/tr-ddns/config.json --udp --tcp &

tr-ddns-ctl --timeout=30 wait || exit 1
tr-ddns-ctl domain ensure dyn.example.com ns=ddns.example.com
tr-ddns-ctl host set www.dyn.example.com a=203.0.113.5
```
