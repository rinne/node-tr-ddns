'use strict'

const EventEmitter = require('node:events');
const dns2 = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');
const DnsCore = require('./dnscore');

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
	#core;

	// The default limit of queries per second from one source.
	static DEFAULT_RATE_LIMIT = DnsCore.DEFAULT_RATE_LIMIT;

	// The options are
	//
	//   nameDB             the database to answer from (required
	//                      unless core is given)
	//   core               a DnsCore to answer with, shared with other
	//                      transports; rateLimit and refuseOutOfZone are
	//                      then its business
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
		if (this.#debug) {
			log.enableDebug();
		}
		this.#closed = false;
		let listeners = [];
		for (let proto of [ 'tcp', 'udp' ]) {
			let name = proto.toUpperCase();
			if (! config?.[proto]) {
				if (this.#debug) {
					log.debug('NameServer: ' + name + ': none');
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
					log.debug('NameServer: ' + name + ':', (address.includes(':') ? ('[' + address + ']') : address) + ':' + port.toString());
				}
			}
		}
		if (! nullish(config?.core)) {
			if (! (config.core instanceof DnsCore)) {
				throw new Error('Invalid DnsCore');
			}
			this.#core = config.core;
		} else {
			this.#core = new DnsCore({ nameDB: config?.nameDB, rateLimit: config?.rateLimit,
									   refuseOutOfZone: config?.refuseOutOfZone, debug: this.#debug });
		}
		if (listeners.length < 1) {
			throw new Error('No listeners');
		}
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
				this.#core.countInvalid();
				if (this.#debug) {
					log.debug('Client sent an invalid request', e);
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
					this.emit('ready');
				}
			}.bind(this));

			server.on('close', function () {
				entry.closed = true;
				if (this.#servers.every((x) => x.closed)) {
					let wasReady = (this.#listening === this.#servers.length);
					this.#closed = true;
					if (this.#debug) {
						log.debug('server closed');
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
		return Promise.all(this.#servers.filter((x) => x.listening).map((x) => this.#closeEntry(x)));
	}

	#query(request, send, rinfo) {
		// Over UDP rinfo describes the sender; over TCP it is the socket.
		let r = this.#core.answer(request, rinfo?.remoteAddress ?? rinfo?.address);
		if (! r.response) {
			return this.#drop(rinfo);
		}
		// Sending can fail when the client has gone away. That is not
		// an error of the server.
		let sent;
		try {
			sent = send(r.response);
		} catch (e) {
			sent = Promise.reject(e);
		}
		Promise.resolve(sent).catch(function(e) {
			if (this.#debug) {
				log.debug('Unable to send a response', e);
			}
		}.bind(this));
	}

	// Counters since the start: queries received, queries answered,
	// and the queries that were dropped by reason.
	stats() {
		return this.#core.stats();
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
