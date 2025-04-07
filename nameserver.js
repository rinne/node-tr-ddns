'use strict'

const EventEmitter = require('node:events');
const dns2 = require('dns2');
const ipaddr = require('ipaddr.js');

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
			this.emit(e);
			this.#server = undefined;
			server.close();
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
		const response = dns2.Packet.createResponseFromRequest(request);
		for (let q of request.questions) {
			if (this.#debug) {
				log('query:', JSON.stringify(q, null, 2));
			}
			if (! (q && (typeof(q) === 'object'))) {
				if (this.#debug) {
					log('response: NONE <invalid-query>');
				}
				continue;
			}
			if (q.class !== dns2.Packet.CLASS.IN) {
				if (this.#debug) {
					log('response: NONE <invalid-query-class>');
				}
				continue;
			}
			let r = this.#db.get(q.name, q.type);
			if (! r) {
				if (this.#debug) {
					log('response: NONE <database-query-returns-null>');
				}
				continue;
			}
			if (this.#debug) {
				log('response:', JSON.stringify(r, null, 2));
			}
			response.answers.push(r);
		}
		send(response);
	}

	close() {
		this.#closed = true;
		if (! this.#server) {
			return;
		}
		this.#server.close();
	}

};

module.exports = NameServer;
