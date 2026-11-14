# Library

The package can be used as a library to embed the name server in
another program. Everything is exported from the main module, and type
declarations are included.

```js
const { NameDB, NameServer, DnsCore, ApiServer, ApiCore, ControlServer, ConfigStore, log } = require('tr-ddns');
```

The modules can also be required one by one, as before version 2.0.0:
`tr-ddns/namedb`, `tr-ddns/nameserver`, `tr-ddns/apiserver`,
`tr-ddns/log`, `tr-ddns/nullish` and `tr-ddns/ts`. Other files of the
package are internal.

## Example

A DNS server for one domain, with the API on the loopback interface and
the contents saved in a file. This example is run by the test suite.

```js
const { NameDB, NameServer, ApiServer, ConfigStore } = require('tr-ddns');

async function start(file, dnsPort, apiPort) {
	const db = new NameDB();
	const store = new ConfigStore({ file: file, nameDB: db });
	try {
		await store.load();
	} catch (e) {
		if (e.code !== 'ENOENT') {
			throw e;
		}
		db.addDomain('example.com', { ns: 'ns1.example.com', ttl: 120 });
		db.set('ns1.example.com', { a: '192.0.2.53' });
	}
	await store.write();
	store.watch();

	const dns = new NameServer({ nameDB: db,
								 udp: true, udpListenAddress: '127.0.0.1', udpListenPort: dnsPort,
								 tcp: true, tcpListenAddress: '127.0.0.1', tcpListenPort: dnsPort });
	const api = new ApiServer({ nameDB: db, nameServer: dns, address: '127.0.0.1', port: apiPort });
	await Promise.all([ new Promise((resolve, reject) => { dns.once('ready', resolve); dns.once('error', reject); }),
						new Promise((resolve, reject) => { api.once('ready', resolve); api.once('error', reject); }) ]);

	db.set('www.example.com', { a: [ '192.0.2.10', '192.0.2.11' ] }, 3600 * 1000);

	return async function stop() {
		await store.flush();
		store.close();
		await api.close();
		await dns.close();
		db.close();
	};
}
```

## NameDB

The domains and hosts. `new NameDB({ debug })`.

Names are not case sensitive and may end with a dot. Methods that take a
name return a failure value for an invalid one; they do not throw, with
the exceptions noted.

| Method | Description |
| --- | --- |
| `addDomain(domain, options)` | Starts serving a domain. `options` are the settings below and `serial`, a serial to continue from. Throws if the name is invalid, if the domain is served already or overlaps a served domain, or if a setting is invalid. |
| `setDomainOptions(domain, options)` | Changes settings of a served domain. Only the settings present are changed; `null` or `''` brings back the default. Returns `false` if the domain is not served; throws for an invalid setting. |
| `getDomain(domain)` | `{ name, lcname, serial, ns, admin, ttl, refresh, retry, expiration, minimum }` with the settings in effect, or `undefined`. |
| `removeDomain(domain)` | Stops serving a domain and removes its hosts. Returns `false` if it was not served. |
| `set(name, data, ttlMs, merge)` | Sets the records of a host; see below. Returns `false`, changing nothing, if anything is invalid. |
| `remove(name)` | Removes a host. Returns `false` if there was none. |
| `getHostData(name)` | The records of a host as `{ a: Set, aaaa: Set, ... }`, with empty sets if the host does not exist. `undefined` for a name outside the served domains, `false` for an invalid name. The sets are copies. |
| `getHostExpires(name)` | When the host expires in milliseconds since the epoch, `null` if it does not, `undefined` if there is no such host. |
| `lookup(name, type)` | What the name server answers to a query: `{ rcode, aa, answers, authorities, additionals }`, or `false` for a name outside the served domains. `type` is the numeric DNS type. |
| `get(name, type)` | The records of one type that the name itself has, as an array of resource records. No aliases or delegations are followed. `false` for an invalid name or a name outside the served domains. |
| `dump()` | Everything as a plain object, in the form of the [configuration file](config-file.md). |
| `flush()` | Removes all hosts and domains. |
| `stats()` | `{ lookup: { total, errors }, domains, hosts }`. |
| `valid(name)`, `validDomain(domain)` | Whether a host name or a domain name is acceptable. |
| `close()` | Stops the timers of the database. Hosts no longer expire after this. Call it when done, or the timers keep the process alive. |

### Domain settings

`ns` (a name or an array of names), `admin` (a mail address or its SOA
form), and the numbers `ttl`, `refresh`, `retry`, `expiration` and
`minimum` in seconds. See [dns.md](dns.md#soa-ns-and-time-to-live).

### set()

`data` is an object with a property for each record type to set: `a`,
`aaaa`, `txt`, `mx`, `cname`, `ns`, `srv`, `caa`. The values are in the
form described in [api.md](api.md#record-types). Each property is

- a string: one value,
- an array or a `Set` of strings: those values,
- an empty string: no values,
- absent, `null` or `undefined`: nothing said about the type.

Without `merge`, the host gets exactly the records in `data`. With
`merge`, a type that is absent keeps its values, a single string is
added to the values of its type, and an array, a `Set` or an empty
string replaces them.

`ttlMs` is the lifetime of the host in milliseconds. Without it, or with
0, the host does not expire, also when `merge` is used on a host that
had a lifetime.

### Events

| Event | Argument | When |
| --- | --- | --- |
| `add` | host name in lower case | A host was created. |
| `update` | host name in lower case | The records of an existing host were set. |
| `remove` | host name in lower case | A host was removed or expired. Not emitted for the hosts of a removed domain. |
| `adddomain` | domain name in lower case | |
| `updatedomain` | domain name in lower case | The settings of a domain were changed. |
| `removedomain` | domain name in lower case | |
| `flush` | | Everything was removed. |

## NameServer

The DNS server. It starts listening when it is created.

| Option | Description | Default |
| --- | --- | --- |
| `nameDB` | The database to answer from. Required unless `core` is given. | |
| `core` | A `DnsCore` to answer with, shared with other transports. `rateLimit` and `refuseOutOfZone` are then set on the core. | one of its own |
| `udp`, `tcp` | Enable the transport. At least one is required. | off |
| `udpListenAddress`, `tcpListenAddress` | An address, a comma separated list of addresses, or an array. | `0.0.0.0` |
| `udpListenPort`, `tcpListenPort` | | 53 |
| `rateLimit` | Queries per second answered to one source; 0 or `false` for no limit. | 500 |
| `refuseOutOfZone` | Answer REFUSED outside the served domains. | off |
| `debug` | Log queries and responses. | off |

The constructor throws for invalid options.

| Member | Description |
| --- | --- |
| `stats()` | The counters described under `dns` in [api.md](api.md#stats). |
| `close()` | Stops listening. Returns a promise. |
| `NameServer.DEFAULT_RATE_LIMIT` | 500. |

| Event | When |
| --- | --- |
| `ready` | All listeners are up. |
| `error` | A listener could not be started; the argument is the error. All listeners are closed. Without a handler for this event the error is thrown, as for any `EventEmitter`. |
| `close` | The listeners have closed after `close()`. |

## DnsCore

Answering DNS queries without a transport: what `NameServer` runs for
each query it receives. Use it to answer DNS over something else. The
rate limit and the counters belong to the core, so servers that share a
core share them.

| Option | Description | Default |
| --- | --- | --- |
| `nameDB` | The database to answer from. Required. | |
| `rateLimit` | Queries per second answered to one source; 0 or `false` for no limit. | 500 |
| `refuseOutOfZone` | Answer REFUSED outside the served domains. | off |
| `debug` | Log queries and responses. | off |

| Member | Description |
| --- | --- |
| `answer(request, source, options)` | Answers one query. `request` is a DNS message parsed with `Packet.parse()` of the `dns2` package, `source` the address it came from. Returns `{ response }`, a packet whose `toBuffer()` gives the bytes to send, or `{ dropped }`, the reason why there is no answer: `notQuery`, `invalid`, `outOfZone`, `rateLimited` or `error`. `options.refuseOutOfZone` overrides the option of the same name for this query. Never throws. |
| `countInvalid()` | Counts a packet that the transport could not parse. |
| `stats()` | The counters described under `dns` in [api.md](api.md#stats). |
| `DnsCore.DEFAULT_RATE_LIMIT` | 500. |

## ApiServer

The HTTP API of [api.md](api.md). It starts listening when it is
created.

| Option | Description | Default |
| --- | --- | --- |
| `nameDB` | The database to manage. Required unless `api` is given. | |
| `api` | An `ApiCore` to serve, shared with other transports. | one of its own |
| `nameServer` | A `NameServer` whose counters are added to `/stats`. | |
| `address` | | `0.0.0.0` |
| `port` | | 80 |
| `basicAuth` | The base64 encoding of `user:password`. Requests must then carry it in HTTP Basic authentication. | none: the API is open |
| `maxBodySize` | The largest request body in bytes. | 65536 |
| `debug` | Log requests. | off |

| Member | Description |
| --- | --- |
| `close()` | Stops listening and closes open connections. Returns a promise. |

| Event | When |
| --- | --- |
| `ready` | The server is listening. |
| `error` | The listener could not be started; the argument is the error. |

## ApiCore

The calls of the API without a transport: what `ApiServer` and the other
HTTP layers of the package run for each request. Use it to offer the API
over something else, or to make calls from the same process.

| Option | Description |
| --- | --- |
| `nameDB` | The database to manage. Required. |
| `nameServer` | An object whose `stats()` is added to `/stats` as `dns`. |
| `dohServer` | An object whose `stats()` is added to `/stats` as `doh`. |
| `debug` | Log details of rejected input. |

| Method | Description |
| --- | --- |
| `handle({ method, path, params })` | Performs one call. `path` is the path of [api.md](api.md) without a query string, `params` an object of parameters. Returns `{ status, body }`: the HTTP status and the JSON object of the response. Never throws. |
| `countCall()`, `countAuthFailure()` | Count a request, and a request refused for missing or wrong credentials, for `/stats`. A transport calls these. |

```js
const { NameDB, ApiCore } = require('tr-ddns');

const db = new NameDB();
const api = new ApiCore({ nameDB: db });
api.handle({ path: '/domain', params: { domain: 'example.com' } });
const result = api.handle({ path: '/host', params: { host: 'www.example.com', a: '192.0.2.10' } });
// result is { status: 200, body: { status: 'ok', code: 200 } }
db.close();
```

To serve one core over several transports, give it to each of them in
the `api` option instead of `nameDB`.

## ControlServer

The API on a Unix domain socket, without authentication. It starts
listening when it is created.

| Option | Description | Default |
| --- | --- | --- |
| `path` | The socket file. Required. | |
| `mode` | The permissions of the socket file, a number or an octal string. | `0600` |
| `api` | An `ApiCore` to serve, shared with other transports. | one of its own |
| `nameDB` | The database to manage. Required unless `api` is given. | |
| `maxBodySize` | The largest request body in bytes. | 65536 |
| `debug` | Log requests. | off |

| Member | Description |
| --- | --- |
| `close()` | Stops listening and removes the socket file. Returns a promise. |

| Event | When |
| --- | --- |
| `ready` | The server is listening. |
| `error` | The socket could not be created; the argument is the error. Its `code` is `EADDRINUSE` when another server listens on the socket and `EEXIST` when the path is a file that is not a socket. |

## ConfigStore

Loads a [configuration file](config-file.md) into a `NameDB` and saves
the database when it changes.

| Option | Description | Default |
| --- | --- | --- |
| `file` | The file. Required. | |
| `nameDB` | The database. Required. | |
| `writeIntervalMs` | The shortest time between two writes in milliseconds. | 10000 |

| Method | Description |
| --- | --- |
| `init()` | Creates the file from the database. Rejects with code `EEXIST` if the file exists. |
| `load()` | Reads the file into the database. Resolves to an array of messages about the entries that were skipped. Rejects with an error whose `code` is `ENOENT` if there is no file, `EMALFORMED` if it is not a configuration, or the code of the file system error. |
| `write(options)` | Writes the database to the file now. With `{ untimed: true }` the write does not count for the write interval. |
| `watch()` | Starts writing the file when the database changes, at most once in the write interval. |
| `flush()` | Writes pending changes now. Use before exiting. |
| `close()` | Stops following the database. Pending changes are not written. |

| Event | When |
| --- | --- |
| `write` | The file was written. |
| `error` | A write started by `watch()` failed; the argument is the error. |

## log

`log(...args)` prints a line with a time stamp, like `console.log`. It
also has `log.error`, `log.warn`, `log.info` and `log.debug`, and
`log.setLevel(level)` and `log.getLevel()` with the levels `none`,
`error`, `warn`, `info` (the default) and `debug`. Creating a component
with `debug: true` sets the level to `debug`.

## nullish and ts

`nullish(x)` is true for `null` and `undefined`. `ts()` returns the
current time as `YYYY-MM-DD HH:MM:SS` in UTC.
