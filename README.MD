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
            --http-api-listen-address=<arg>  Listen address for HTTP control server
            --http-api-listen-port=<arg>     Listen port for HTTP-API server
  -h        --help                           Show help and exit
```

## API

All API methods work either with GET method and URL parameters or POST method with JSON payload.

### Add Domain

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld'
```

### Remove Domain

```
curl 'http://TR-DDNS-ADDR/domain?domain=test-domain.tld&remove=true'
```

### Add or Update Host

Supported records are A, AAAA, and TXT. All records must be set on a single call.

```
curl http://TR-DDNS/host'?host=host1.test.domain.tld?a=1.2.3.4'
curl http://TR-DDNS/host'?host=host2.test.domain.tld?a=1.2.3.4&aaaa=2001:ffff:ffff::dead:beef'
curl http://TR-DDNS/host'?host=_sometext.test.domain.tld?txt=this-is-probably-some-dynamic-authorization'
```

Lifetime can be set by ttl parameter, which makes the record disappear after the given number of seconds.

```
curl http://TR-DDNS/host'?host=_hello.test.domain.tld?txt=hello&ttl=3600'
```

### Remove Host

```
curl http://TR-DDNS/host'?host=_hello.test.domain.tld?remove=true
```

## Author

Timo J. Rinne <tri@iki.fi>


## License

MIT License
