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
            --udp                            Enable UDP server
            --udp-listen-address=<arg>       Listen address for UDP server
            --udp-listen-port=<arg>          Listen port for UDP server
            --tcp                            Enable TCP server
            --tcp-listen-address=<arg>       Listen address for TCP server
            --tcp-listen-port=<arg>          Listen port for TCP server
            --http-api                       Enable HTTP-API server
            --http-api-user=<arg>            Required username for HTTP API server
            --http-api-password=<arg>        Required passwordname for HTTP API server
            --http-api-listen-address=<arg>  Listen address for HTTP control server
            --http-api-listen-port=<arg>     Listen port for HTTP-API server
  -h        --help                           Show help and exit
```

## API

All API methods work either with GET method and URL parameters or POST
method with JSON payload. Every response is JSON of the form
`{ "status": "ok", "code": 200, "data": ... }` or
`{ "status": "error", "code": 400, "message": "..." }`, and the HTTP
status is the same as `code`.

If `--http-api-user` and `--http-api-password` are given, every call
needs HTTP Basic authentication (`curl -u user:password ...`).

Every option can also be given in the environment as
`TR_DDNS_OPT_<OPTION NAME>`, for example `TR_DDNS_OPT_UDP_LISTEN_PORT=5353`
or `TR_DDNS_OPT_HTTP_API=true`.

### Add Domain

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld'
```

Fails if the domain already exists or if there is already a domain,
which is either a parent domain or a subdomain of the domain that is
added.

### Remove Domain

Removes also all host records under that domain.

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&remove=true'
```

### Add or Update Host

Supported records are A, AAAA, MX, and TXT.

```
curl 'http://TR-DDNS-ADDR/host?host=host1.test-domain.tld&a=1.2.3.4'
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
no `value` needed). `type` is `a`, `aaaa`, `txt` or `mx`.

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
