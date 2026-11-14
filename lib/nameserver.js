'use strict'

const EventEmitter = require('node:events');
const dns2 = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');

class NameServer extends EventEmitter {

	#server;
	#closed;
	#debug;
	#db;
	#stat;
	#rateLimit;
	#rateCounts;
	#rateTimer;

	// The default limit of queries per second from one source.
	static DEFAULT_RATE_LIMIT = 500;

	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#closed = false;
		this.#stat = { queries: 0, answered: 0, nxdomain: 0, empty: 0,
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
		let listen = {};
		if (config?.tcp) {
			listen.tcp = {
				port: config?.tcpListenPort ?? 53,
				address: config?.tcpListenAddress ?? '0.0.0.0'
			};
			if (! ipaddr.isValid(listen.tcp.address)) {
				throw new Error('Invalid TCP listen address');
			}
			if (! (Number.isSafeInteger(listen.tcp.port) && (listen.tcp.port >= 0x0001) && (listen.tcp.port <= 0xffff))) {
				throw new Error('Invalid TCP listen port');
			}
			if (this.#debug) {
				log('NameServer: TCP:', listen.tcp.address + ':' + listen.tcp.port.toString());
			}
		} else {
			if (this.#debug) {
				log('NameServer: TCP: none');
			}
		}
		if (config?.udp) {
			listen.udp = {
				port: config?.udpListenPort ?? 53,
				address: config?.udpListenAddress ?? '0.0.0.0'
			};
			if (ipaddr.IPv4.isValid(listen.udp.address)) {
				listen.udp.type = 'udp4';
			} else if (ipaddr.IPv6.isValid(listen.udp.address)) {
				listen.udp.type = 'udp6';
			} else {
				throw new Error('Invalid UDP listen address');
			}
			if (! (Number.isSafeInteger(listen.udp.port) && (listen.udp.port >= 0x0001) && (listen.udp.port <= 0xffff))) {
				throw new Error('Invalid UDP listen port');
			}
			if (this.#debug) {
				log('NameServer: UDP:', listen.udp.address + ':' + listen.udp.port.toString());
			}
		} else {
			if (this.#debug) {
				log('NameServer: UDP: none');
			}
		}
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		if (! (listen.tcp || listen.udp)) {
			throw new Error('No listeners');
		}
		this.#db = config.nameDB;
		let server = dns2.createServer({
			udp: listen.udp ? true : false,
			tcp: listen.tcp ? true : false,
			handle: function(request, send, rinfo) { return this.#query(request, send, rinfo); }.bind(this)
		});

		server.on('request', function (request, response, rinfo) {
			/*NOTHING*/;
		}.bind(this));

		server.on('requestError', function (e) {
			this.#stat.dropped.invalid++;
			if (this.#debug) {
				log('Client sent an invalid request', e);
			}
		}.bind(this));

		server.on('error', function (e) {
			this.#server = undefined;
			this.#closed = true;
			this.#stopRateTimer();
			try {
				server.close();
			} catch (ignored) {
				/*NOTHING*/
			}
			this.emit('error', e);
		}.bind(this));

		server.on('listening', function () {
			if (this.#closed) {
				server.close();
				return;
			}
			this.#server = server;
			if (this.#rateLimit > 0) {
				// The counters are per second.
				this.#rateTimer = setInterval(function() { this.#rateCounts.clear(); }.bind(this), 1000);
				this.#rateTimer.unref();
			}
			this.emit('ready');
		}.bind(this));

		server.on('close', function () {
			this.#closed = true;
			this.#stopRateTimer();
			if (! this.#server) {
				return;
			}
			if (this.#debug) {
				log('server closed');
			}
			this.#server = undefined;
			this.emit('close');
		}.bind(this));

		server.listen(listen);
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
		if (r === false) {
			// Query didn't match to any domain we are serving, so
			// we don't bother answering. It's probably a
			// configuration error, hostile probing, or DNS
			// applification attack anyways.
			this.#stat.dropped.outOfZone++;
			if (this.#debug) {
				log('response: NONE <not-allowed> (' + q.name + ')');
			}
			return this.#drop(rinfo);
		}
		const response = dns2.Packet.createResponseFromRequest(request);
		response.header.rcode = r.rcode;
		response.answers.push(...r.answers);
		if (r.rcode === dns2.Packet.RCODE.NXDOMAIN) {
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
		this.#closed = true;
		this.#stopRateTimer();
		if (! this.#server) {
			return Promise.resolve();
		}
		return Promise.resolve(this.#server.close()).then(function() { return undefined; });
	}

};

module.exports = NameServer;
