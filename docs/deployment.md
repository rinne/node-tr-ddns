# Deployment

How to put a dynamic zone on the Internet with `tr-ddns`: delegate a
domain to the server, let it use port 53, keep the API out of reach, and
run it as a service.

## Delegating a domain to the server

`tr-ddns` serves whole domains. The usual arrangement is to give it a
subdomain of a domain you already have, say `dyn.example.com`, and leave
the rest of `example.com` where it is.

1. Give the machine that runs `tr-ddns` a name in the parent zone, with
   its public address. In the zone of `example.com`, at your DNS
   provider:

   ```
   ddns.example.com.   IN  A     203.0.113.5
   ```

2. Delegate the subdomain to that name, in the same zone:

   ```
   dyn.example.com.    IN  NS    ddns.example.com.
   ```

3. Add the domain to `tr-ddns` with the same name server, so that what
   the server says about itself agrees with the delegation:

   ```
   curl 'http://127.0.0.1:8080/domain?domain=dyn.example.com&ns=ddns.example.com&admin=hostmaster@example.com'
   ```

4. Add hosts:

   ```
   curl 'http://127.0.0.1:8080/host?host=home.dyn.example.com&a=198.51.100.7'
   ```

5. Check from outside:

   ```
   dig home.dyn.example.com A
   dig @203.0.113.5 dyn.example.com SOA
   ```

Without the `ns` setting the domain names itself as its name server.
That works too, provided the domain has an address record of its own
(`/host?host=dyn.example.com&a=203.0.113.5`), but naming the real server
is clearer.

Resolvers reach the server over UDP and, for large answers, TCP. Open
port 53 for both in the firewall, and start the server with both `--udp`
and `--tcp`.

With a single server there is no redundancy: while it is down, names in
the domain do not resolve once their short time to live has passed.
`tr-ddns` does not do zone transfers, so a second server cannot follow
the first one.

## Listening on port 53

Ports below 1024 need a privilege. In order of preference:

- **systemd.** Let the service manager grant the one capability needed;
  see the unit below.
- **A capability on the Node.js binary** (Linux):
  `setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v node)")"`.
  It applies to every program run with that binary.
- **A high port and a redirect.** Run with `--udp-listen-port=5300
  --tcp-listen-port=5300` and redirect port 53 to it in the firewall.
- **Root.** It works, and the server then runs with far more privilege
  than it needs. `tr-ddns` does not drop privileges after binding.

On machines where a local resolver already holds port 53 on the loopback
address (systemd-resolved, dnsmasq), listen on the public address
instead of `0.0.0.0`: `--udp-listen-address=203.0.113.5
--tcp-listen-address=203.0.113.5`.

## Securing the API

The API can change and remove everything, and by default it listens on
`0.0.0.0` port 80 without authentication. Do not leave it like that on a
machine that is reachable from the Internet.

- **Only local clients.** `--http-api-listen-address=127.0.0.1`. Scripts
  on the same machine use it directly; others reach it through SSH or a
  reverse proxy.
- **Remote clients.** Set `--http-api-user` and
  `--http-api-password-file`, and put a reverse proxy that does TLS in
  front, with the API itself on `127.0.0.1`. The API speaks plain HTTP,
  and Basic authentication over plain HTTP gives the password to anyone
  on the path.
- Keep the password out of the command line, where every local user can
  see it. Use `--http-api-password-file` with a file only the service
  user can read, or `TR_DDNS_OPT_HTTP_API_PASSWORD` in the environment
  of the service.

There is one user with full access. A client that updates a single
address can also flush the database, so give the credentials only to
clients you trust with all of it.

## Running as a service

A systemd unit, with the files in `/var/lib/tr-ddns` and a dedicated
user:

```ini
[Unit]
Description=tr-ddns dynamic DNS server
After=network-online.target
Wants=network-online.target

[Service]
User=tr-ddns
Group=tr-ddns
StateDirectory=tr-ddns
ExecStartPre=/bin/sh -c 'test -e /var/lib/tr-ddns/config.json || /usr/bin/tr-ddns -c /var/lib/tr-ddns/config.json --init-config-file'
ExecStart=/usr/bin/tr-ddns -c /var/lib/tr-ddns/config.json --udp --tcp --http-api --http-api-listen-address=127.0.0.1 --http-api-listen-port=8080
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Adjust the path of `tr-ddns` to where npm installed it (`command -v
tr-ddns`). The configuration file is replaced through a temporary file
next to it, so the service user needs write access to the directory, not
only to the file; `StateDirectory` takes care of that.

`systemctl stop` sends SIGTERM, on which the server writes pending
changes and exits with status 0.

The options can also come from the environment, for example from an
`EnvironmentFile`:

```
TR_DDNS_OPT_UDP=true
TR_DDNS_OPT_TCP=true
TR_DDNS_OPT_HTTP_API=true
TR_DDNS_OPT_HTTP_API_LISTEN_ADDRESS=127.0.0.1
TR_DDNS_OPT_HTTP_API_LISTEN_PORT=8080
TR_DDNS_OPT_HTTP_API_USER=admin
TR_DDNS_OPT_HTTP_API_PASSWORD_FILE=/etc/tr-ddns/password
```

## Recipes

### A home address that changes

On the machine whose address changes, run this from cron or a timer. The
lifetime makes the name disappear if the updates stop.

```
curl -fsS -u admin:secret "https://ddns.example.com/host?host=home.dyn.example.com&a=$(curl -fsS https://api.ipify.org)&ttl=3600"
```

### Certificates with the ACME DNS-01 challenge

A certificate authority checks a TXT record at
`_acme-challenge.<name>`. To answer challenges for names in a zone that
is not dynamic, point the challenge name to the dynamic zone once, in
the static zone:

```
_acme-challenge.www.example.com.  IN  CNAME  www.acme.dyn.example.com.
```

The ACME client then only needs to set a TXT record in the dynamic zone,
with a lifetime so that it cleans up after itself:

```
curl 'http://127.0.0.1:8080/host?host=www.acme.dyn.example.com&txt=TOKEN&ttl=600'
```

For a wildcard certificate together with the base name the authority
asks for two tokens at the same name; add the second one with
`/record?host=www.acme.dyn.example.com&command=add&type=txt&value=TOKEN2`.
