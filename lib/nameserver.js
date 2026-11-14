'use strict'

const EventEmitter = require('node:events');
const dns2 = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');

// The UDP payload size offered to clients that use EDNS. It avoids
// fragmentation on practically every path.
const EDNS_UDP_PAYLOAD_SIZE = 1232;

// A listen address option as a list of addresses: a single address, a
// comma separated list or an array.
function addressList(value, fallback, what) {
	let list = value ?? fallback;
	if (typeof(list) === 'string') {
		list = list.split(',').map((x) => x.trim());
	}
	if (! (Array.isArray(list) && (list.length > 0) && list.every((x) => ((typeof(x) === 'string') && ipaddr.isValid(x))))) {
		throw new Error('Invalid ' + what + ' listen address');
	}
	return Array.from(new Set(list));
}

class NameServer extends EventEmitter {

	#servers;
	#listening;
	#closed;
	#debug;
	#db;
	#stat;
	#rateLimit;
	#rateCounts;
	#rateTimer;
	#refuse;

	// The default limit of queries per second from one source.
	static DEFAULT_RATE_LIMIT = 500;

	// The options are
	//
	//   nameDB             the database to answer from (required)
	//   udp, tcp           enable the transport
	//   udpListenAddress, tcpListenAddress
	//                      an address, a comma separated list of
	//                      addresses or an array (default 0.0.0.0)
	//   udpListenPort, tcpListenPort
	//                      the port (default 53)
	//   rateLimit          queries per second answered to one source,
	//                      0 for no limit (default 500)
	//   refuseOutOfZone    answer REFUSED to queries for names outside
	//                      the served domains instead of staying silent
	//   debug              log queries and responses
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#closed = false;
		this.#refuse = config?.refuseOutOfZone ? true : false;
		this.#stat = { queries: 0, answered: 0, nxdomain: 0, empty: 0, refused: 0,
					   dropped: { notQuery: 0, invalid: 0, outOfZone: 0, rateLimited: 0, error: 0 } };
		if (nullish(config?.rateLimit)) {
			this.#rateLimit = NameServer.DEFAULT_RATE_LIMIT;
		} else if ((config.rateLimit === 0) || (config.rateLimit === false)) {
			this.#rateLimit = 0;
		} else if (Number.isSafeInteger(config.rateLimit) && (config.rateLimit > 0)) {
			this.#rateLimit = config.rateLimit;
		} else {
			throw new Error('Invalid rate limit');
		}
		this.#rateCounts = new Map();
		this.#rateTimer = null;
		let listeners = [];
		for (let proto of [ 'tcp', 'udp' ]) {
			let name = proto.toUpperCase();
			if (! config?.[proto]) {
				if (this.#debug) {
					log('NameServer: ' + name + ': none');
				}
				continue;
			}
			let port = config?.[proto + 'ListenPort'] ?? 53;
			let addresses = addressList(config?.[proto + 'ListenAddress'], '0.0.0.0', name);
			if (! (Number.isSafeInteger(port) && (port >= 0x0001) && (port <= 0xffff))) {
				throw new Error('Invalid ' + name + ' listen port');
			}
			for (let address of addresses) {
				listeners.push({ proto, address, port, ipv6: ipaddr.IPv6.isValid(address) });
				if (this.#debug) {
					log('NameServer: ' + name + ':', (address.includes(':') ? ('[' + address + ']') : address) + ':' + port.toString());
				}
			}
		}
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		if (listeners.length < 1) {
			throw new Error('No listeners');
		}
		this.#db = config.nameDB;
		this.#servers = [];
		this.#listening = 0;
		// Each address and transport has a server of its own.
		for (let l of listeners) {
			let server = dns2.createServer({
				udp: (l.proto === 'udp') ? { type: l.ipv6 ? 'udp6' : 'udp4' } : false,
				tcp: (l.proto === 'tcp'),
				handle: function(request, send, rinfo) { return this.#query(request, send, rinfo); }.bind(this)
			});
			let entry = { server: server, listening: false, closed: false };
			this.#servers.push(entry);

			server.on('requestError', function (e) {
				this.#stat.dropped.invalid++;
				if (this.#debug) {
					log('Client sent an invalid request', e);
				}
			}.bind(this));

			server.on('error', function (e) {
				// One listener that fails takes the others with it.
				let first = (! this.#closed);
				this.#shutdown();
				if (first) {
					this.emit('error', e);
				}
			}.bind(this));

			server.on('listening', function () {
				entry.listening = true;
				if (this.#closed) {
					this.#closeEntry(entry);
					return;
				}
				this.#listening++;
				if (this.#listening === this.#servers.length) {
					if (this.#rateLimit > 0) {
						// The counters are per second.
						this.#rateTimer = setInterval(function() { this.#rateCounts.clear(); }.bind(this), 1000);
						this.#rateTimer.unref();
					}
					this.emit('ready');
				}
			}.bind(this));

			server.on('close', function () {
				entry.closed = true;
				if (this.#servers.every((x) => x.closed)) {
					let wasReady = (this.#listening === this.#servers.length);
					this.#closed = true;
					this.#stopRateTimer();
					if (this.#debug) {
						log('server closed');
					}
					if (wasReady) {
						this.emit('close');
					}
				}
			}.bind(this));

			server.listen({ [l.proto]: { port: l.port, address: l.address } });
		}
	}

	#closeEntry(entry) {
		if (entry.closing) {
			return entry.closing;
		}
		try {
			entry.closing = Promise.resolve(entry.server.close()).catch(function() { /*NOTHING*/ });
		} catch (ignored) {
			entry.closing = Promise.resolve();
		}
		return entry.closing;
	}

	#shutdown() {
		this.#closed = true;
		this.#stopRateTimer();
		return Promise.all(this.#servers.filter((x) => x.listening).map((x) => this.#closeEntry(x)));
	}

	#stopRateTimer() {
		if (this.#rateTimer) {
			clearInterval(this.#rateTimer);
			this.#rateTimer = null;
		}
		this.#rateCounts.clear();
	}

	// The key that queries are counted under: the address for IPv4,
	// the /64 prefix for IPv6, where one client typically has many
	// addresses.
	#rateKey(rinfo) {
		let address = rinfo?.remoteAddress ?? rinfo?.address;
		if (typeof(address) !== 'string') {
			return undefined;
		}
		try {
			let a = ipaddr.parse(address);
			if ((a.kind() === 'ipv6') && a.isIPv4MappedAddress()) {
				a = a.toIPv4Address();
			}
			if (a.kind() === 'ipv6') {
				return a.toNormalizedString().split(':').slice(0, 4).join(':');
			}
			return a.toString();
		} catch (e) {
			return address;
		}
	}

	// Returns true if the source of the query has used up its share
	// for the current second.
	#rateLimited(rinfo) {
		if (this.#rateLimit < 1) {
			return false;
		}
		let key = this.#rateKey(rinfo);
		if (key === undefined) {
			return false;
		}
		let n = (this.#rateCounts.get(key) ?? 0) + 1;
		if ((n === 1) && (this.#rateCounts.size >= 65536)) {
			// A flood from a huge number of sources. Start counting
			// from scratch instead of growing without a bound.
			this.#rateCounts.clear();
		}
		this.#rateCounts.set(key, n);
		return (n > this.#rateLimit);
	}

	#query(request, send, rinfo) {
		try {
			return this.#answer(request, send, rinfo);
		} catch (e) {
			// Nothing a client sends may take the server down.
			this.#stat.dropped.error++;
			if (this.#debug) {
				log('response: NONE <error>', e);
			}
			return this.#drop(rinfo);
		}
	}

	#answer(request, send, rinfo) {
		this.#stat.queries++;
		if (this.#rateLimited(rinfo)) {
			this.#stat.dropped.rateLimited++;
			return this.#drop(rinfo);
		}
		let header = request?.header;
		// Only plain queries with exactly one question are served.
		// Responses, other operations (UPDATE, NOTIFY and so on) and
		// packets with several questions are ignored.
		if (! (header && (header.qr === 0) && (header.opcode === 0) &&
			   Array.isArray(request.questions) && (request.questions.length === 1))) {
			this.#stat.dropped.notQuery++;
			if (this.#debug) {
				log('response: NONE <not-a-query>');
			}
			return this.#drop(rinfo);
		}
		let q = request.questions[0];
		if (this.#debug) {
			log('query:', JSON.stringify(q, null, 2));
		}
		if (! ((q?.class === dns2.Packet.CLASS.IN) && Number.isSafeInteger(q?.type) && (typeof(q?.name) === 'string'))) {
			this.#stat.dropped.invalid++;
			if (this.#debug) {
				log('response: NONE <invalid-query>');
			}
			return this.#drop(rinfo);
		}
		let r;
		if (typeof(this.#db.lookup) === 'function') {
			r = this.#db.lookup(q.name, q.type);
		} else {
			// A database that only has the older get() interface.
			let answers = this.#db.get(q.name, q.type);
			r = (answers === false) ? false : { rcode: dns2.Packet.RCODE.NOERROR, answers: answers ?? [] };
		}
		const response = dns2.Packet.createResponseFromRequest(request);
		// A client that uses EDNS gets an OPT record back.
		let edns = (request.additionals ?? []).some((x) => (x?.type === dns2.Packet.TYPE.EDNS));
		if (r === false) {
			// Query didn't match to any domain we are serving, so
			// we don't bother answering. It's probably a
			// configuration error, hostile probing, or DNS
			// applification attack anyways.
			if (! this.#refuse) {
				this.#stat.dropped.outOfZone++;
				if (this.#debug) {
					log('response: NONE <not-allowed> (' + q.name + ')');
				}
				return this.#drop(rinfo);
			}
			this.#stat.refused++;
			r = { rcode: dns2.Packet.RCODE.REFUSED, aa: false, answers: [] };
		}
		response.header.rcode = r.rcode;
		response.header.aa = (r.aa ?? true) ? 1 : 0;
		response.answers.push(...r.answers);
		response.authorities.push(...(r.authorities ?? []));
		response.additionals.push(...(r.additionals ?? []));
		if (edns) {
			response.additionals.push(Object.assign({ name: '' }, dns2.Packet.Resource.EDNS([], { udpPayloadSize: EDNS_UDP_PAYLOAD_SIZE })));
		}
		if (r.rcode === dns2.Packet.RCODE.REFUSED) {
			/*NOTHING*/
		} else if (r.rcode === dns2.Packet.RCODE.NXDOMAIN) {
			this.#stat.nxdomain++;
		} else if (r.answers.length < 1) {
			// We don't have data that was asked for, but the
			// query was at least inside our domains.
			this.#stat.empty++;
		}
		if (this.#debug) {
			log('response:', JSON.stringify(r.answers, null, 2));
		}
		this.#stat.answered++;
		// Sending can fail when the client has gone away. That is not
		// an error of the server.
		Promise.resolve(send(response)).catch(function(e) {
			if (this.#debug) {
				log('Unable to send a response', e);
			}
		}.bind(this));
	}

	// Counters since the start: queries received, queries answered,
	// and the queries that were dropped by reason.
	stats() {
		let rv = Object.assign({}, this.#stat);
		rv.dropped = Object.assign({}, this.#stat.dropped);
		return rv;
	}

	// A query that gets no answer. Over TCP the connection is closed,
	// because the server library keeps a connection open for as long
	// as it has a query without a response.
	#drop(rinfo) {
		if (typeof(rinfo?.destroy) === 'function') {
			rinfo.destroy();
		}
	}

	// Returns a promise that resolves when the listeners have closed.
	close() {
		return this.#shutdown().then(function() { return undefined; });
	}

};

module.exports = NameServer;
