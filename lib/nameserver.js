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
	
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#closed = false;
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
			log('Client sent an invalid request', e);
		}.bind(this));

		server.on('error', function (e) {
			this.#server = undefined;
			this.#closed = true;
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
			this.emit('ready');
		}.bind(this));

		server.on('close', function () {
			this.#closed = true;
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

	#query(request, send, rinfo) {
		let header = request?.header;
		// Only plain queries with exactly one question are served.
		// Responses, other operations (UPDATE, NOTIFY and so on) and
		// packets with several questions are ignored.
		if (! (header && (header.qr === 0) && (header.opcode === 0) &&
			   Array.isArray(request.questions) && (request.questions.length === 1))) {
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
			log('response: NONE <not-allowed> (' + q.name + ')');
			return this.#drop(rinfo);
		}
		const response = dns2.Packet.createResponseFromRequest(request);
		response.header.rcode = r.rcode;
		if (r.answers.length < 1) {
			// We don't have data that was asked for, but the
			// query was at least inside our domains.
			log('response: NONE <not-found> (' + q.name + ')');
		} else if (this.#debug) {
			log('response:', JSON.stringify(r.answers, null, 2));
		}
		response.answers.push(...r.answers);
		send(response);
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
		if (! this.#server) {
			return Promise.resolve();
		}
		return Promise.resolve(this.#server.close()).then(function() { return undefined; });
	}

};

module.exports = NameServer;
