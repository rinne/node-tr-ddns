'use strict'

// DNS over HTTP as in RFC 8484, without the TLS: the /dns-query
// resource in plain HTTP, meant to sit behind a reverse proxy that
// terminates HTTPS. It serves that one resource and nothing else.

const EventEmitter = require('node:events');
const http = require('node:http');

const { Packet } = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');
const DnsCore = require('./dnscore');
const listener = require('./listener');

const DOH_PATH = '/dns-query';
const DNS_MESSAGE = 'application/dns-message';

// The largest DNS message there can be.
const MAX_MESSAGE_SIZE = 65535;

// How long a request body may take to arrive.
const BODY_READ_TIMEOUT_MS = 5000;

// The most proxies that can be trusted in front of the server.
const MAX_PROXY_HOPS = 32;

class HttpError extends Error {
	constructor(code, message, headers) {
		super(message);
		this.code = code;
		this.headers = headers;
	}
}

class DohServer extends EventEmitter {

	#server;
	#where;
	#core;
	#debug;
	#hops;
	#stat;
	#closed;
	#started;

	// The options are
	//
	//   core              a DnsCore to answer with, shared with the other
	//                     transports, or
	//   nameDB            the database, for a core of its own
	//   address, port     where to listen (default 127.0.0.1, 8053)
	//   socket            a Unix domain socket to listen on instead
	//   socketMode        the permissions of the socket file, a number or
	//                     an octal string (default 0666)
	//   trustedProxyHops  how many proxies in front add the address of
	//                     their client to X-Forwarded-For and are trusted
	//                     to do so (default 0: the header is ignored)
	//   rateLimit         for a core of its own; see DnsCore
	//   debug             log requests
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		this.#hops = config?.trustedProxyHops ?? 0;
		if (! (Number.isSafeInteger(this.#hops) && (this.#hops >= 0) && (this.#hops <= MAX_PROXY_HOPS))) {
			throw new Error('Invalid number of trusted proxy hops');
		}
		if (! nullish(config?.socket)) {
			if (! ((typeof(config.socket) === 'string') && (config.socket !== ''))) {
				throw new Error('Invalid DoH socket path');
			}
			this.#where = { path: config.socket, mode: listener.parseMode(config?.socketMode, 0o666) };
		} else {
			let address = config?.address ?? '127.0.0.1';
			let port = config?.port ?? 8053;
			if (! ((typeof(address) === 'string') && ipaddr.isValid(address))) {
				throw new Error('Invalid DoH listen address');
			}
			if (! (Number.isSafeInteger(port) && (port >= 0x0001) && (port <= 0xffff))) {
				throw new Error('Invalid DoH listen port');
			}
			this.#where = { address: address, port: port };
		}
		if (! nullish(config?.core)) {
			if (! (config.core instanceof DnsCore)) {
				throw new Error('Invalid DnsCore');
			}
			this.#core = config.core;
		} else {
			this.#core = new DnsCore({ nameDB: config?.nameDB, rateLimit: config?.rateLimit, debug: this.#debug });
		}
		this.#stat = { requests: 0, answered: 0, badRequest: 0, notFound: 0, rateLimited: 0, errors: 0 };
		this.#closed = false;
		this.#server = http.createServer(function(req, res) { this.#request(req, res); }.bind(this));
		this.#server.headersTimeout = BODY_READ_TIMEOUT_MS;
		this.#server.requestTimeout = BODY_READ_TIMEOUT_MS + 1000;
		this.#started = listener.listen(this.#server, this.#where)
			.then(function() {
				if (this.#closed) {
					return listener.close(this.#server, this.#where);
				}
				if (this.#debug) {
					log.debug('DohServer:', this.#where.path ?? (this.#where.address + ':' + this.#where.port));
				}
				this.emit('ready');
			}.bind(this))
			.catch(function(e) {
				if (! this.#closed) {
					this.#closed = true;
					this.emit('error', e);
				}
			}.bind(this));
	}

	// Stops listening. Returns a promise.
	async close() {
		this.#closed = true;
		await this.#started;
		await listener.close(this.#server, this.#where);
	}

	// Counters since the start: requests received and how they ended.
	stats() {
		return Object.assign({}, this.#stat);
	}

	// The address that the query is counted under for the rate limit.
	// It is the peer of the connection, unless proxies in front are
	// trusted: with n hops it is the n-th address from the right in
	// X-Forwarded-For, which the outermost trusted proxy put there.
	// Whatever is further left came from the client and proves nothing.
	#client(req) {
		// A connection through a Unix socket has no address. All of
		// them count as one source.
		let peer = req.socket?.remoteAddress ?? 'unix-socket';
		if (this.#hops < 1) {
			return peer;
		}
		let header = req.headers['x-forwarded-for'];
		if (typeof(header) !== 'string') {
			return peer;
		}
		let entries = header.split(',').map((x) => x.trim()).filter((x) => (x !== ''));
		if (entries.length < this.#hops) {
			return peer;
		}
		let candidate = entries[entries.length - this.#hops];
		// An address may come with a port: 192.0.2.1:1234 or [2001:db8::1]:1234.
		let m = candidate.match(/^\[([^\]]+)\](?::\d+)?$/) ?? candidate.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/);
		if (m) {
			candidate = m[1];
		}
		return ipaddr.isValid(candidate) ? candidate : peer;
	}

	#fail(res, e) {
		let code = (e instanceof HttpError) ? e.code : 500;
		if (code === 404) {
			this.#stat.notFound++;
		} else if (code === 429) {
			this.#stat.rateLimited++;
		} else if (code >= 500) {
			this.#stat.errors++;
			log.error('DohServer:', e);
		} else {
			this.#stat.badRequest++;
		}
		if (res.headersSent || res.writableEnded) {
			return;
		}
		let text = ((code >= 500) ? 'Internal Server Error' : e.message) + '\n';
		res.writeHead(code, Object.assign({ 'Content-Type': 'text/plain; charset=utf-8',
											'Content-Length': Buffer.byteLength(text),
											'Cache-Control': 'no-store',
											'Connection': 'close' },
										  (e instanceof HttpError) ? e.headers : undefined));
		res.end(text);
	}

	#request(req, res) {
		this.#stat.requests++;
		this.#message(req)
			.then(function(message) {
				let request;
				try {
					request = Packet.parse(message);
				} catch (e) {
					this.#core.countInvalid();
					throw new HttpError(400, 'Not a DNS message');
				}
				// HTTP cannot stay silent, so a name that the DNS port
				// would ignore is refused here.
				let r = this.#core.answer(request, this.#client(req), { refuseOutOfZone: true });
				if (! r.response) {
					switch (r.dropped) {
					case 'rateLimited':
						throw new HttpError(429, 'Too Many Requests', { 'Retry-After': '1' });
					case 'error':
						throw new Error('Unable to answer');
					default:
						throw new HttpError(400, 'Not a DNS query that can be answered');
					}
				}
				let body = r.response.toBuffer();
				this.#stat.answered++;
				res.writeHead(200, { 'Content-Type': DNS_MESSAGE,
									 'Content-Length': body.length,
									 'Cache-Control': this.#cacheControl(r.response) });
				res.end(body);
			}.bind(this))
			.catch(function(e) {
				this.#fail(res, e);
			}.bind(this));
	}

	// How long the answer may be cached: as long as the record in it
	// that expires first, as RFC 8484 says. For an answer without
	// records that is the SOA record in the authority section.
	#cacheControl(response) {
		if (! [ Packet.RCODE.NOERROR, Packet.RCODE.NXDOMAIN ].includes(response.header.rcode)) {
			return 'no-store';
		}
		let rrs = (response.answers.length > 0) ? response.answers : response.authorities;
		let ttls = rrs.map((x) => x.ttl).filter((x) => Number.isSafeInteger(x));
		if (ttls.length < 1) {
			return 'no-store';
		}
		return 'max-age=' + Math.max(0, Math.min(...ttls)).toString();
	}

	// The DNS message of a request as a buffer.
	async #message(req) {
		let url = req.url ?? '';
		let q = url.indexOf('?');
		let path = (q < 0) ? url : url.slice(0, q);
		if (path !== DOH_PATH) {
			throw new HttpError(404, 'Not Found');
		}
		let message;
		if (req.method === 'GET') {
			let dns = (new URLSearchParams((q < 0) ? '' : url.slice(q + 1))).get('dns');
			if (dns === null) {
				throw new HttpError(400, 'Parameter dns is missing');
			}
			dns = dns.replace(/=+$/, '');
			// The HTTP server limits the size of the request line, so the
			// message cannot be too large here.
			if (! /^[A-Za-z0-9_-]+$/.test(dns)) {
				throw new HttpError(400, 'Parameter dns is not base64url');
			}
			message = Buffer.from(dns, 'base64url');
		} else if (req.method === 'POST') {
			let type = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
			if (type !== DNS_MESSAGE) {
				throw new HttpError(415, 'Content type must be ' + DNS_MESSAGE);
			}
			message = await this.#body(req);
		} else {
			throw new HttpError(405, 'Method Not Allowed', { 'Allow': 'GET, POST' });
		}
		// A DNS message has at least a header of twelve bytes.
		if (message.length < 12) {
			this.#core.countInvalid();
			throw new HttpError(400, 'Not a DNS message');
		}
		return message;
	}

	#body(req) {
		return new Promise(function(resolve, reject) {
			let chunks = [];
			let size = 0;
			let timer = setTimeout(function() { reject(new HttpError(408, 'Request Timeout')); }, BODY_READ_TIMEOUT_MS);
			req.on('data', function(d) {
				size += d.length;
				if (size > MAX_MESSAGE_SIZE) {
					clearTimeout(timer);
					reject(new HttpError(413, 'Payload Too Large'));
					return;
				}
				chunks.push(d);
			});
			req.on('end', function() {
				clearTimeout(timer);
				resolve(Buffer.concat(chunks));
			});
			req.on('error', function() {
				clearTimeout(timer);
				reject(new HttpError(400, 'Unable to read the request'));
			});
		});
	}

}

module.exports = DohServer;
