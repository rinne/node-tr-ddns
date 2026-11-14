'use strict'

// The API on a Unix domain socket, for the programs on the same
// machine that are in charge of the server. There is no network port
// and no authentication: whoever can open the socket file can do
// everything, so access is a matter of file permissions.

const EventEmitter = require('node:events');
const http = require('node:http');

const nullish = require('./nullish');
const log = require('./log');
const ApiCore = require('./api');
const listener = require('./listener');

// The largest request body accepted, in bytes.
const DEFAULT_MAX_BODY_SIZE = 65536;

// How long a request body may take to arrive.
const BODY_READ_TIMEOUT_MS = 5000;

const DANGEROUS_NAMES = new Set([ '__proto__', 'constructor', 'prototype' ]);

// A request that is answered with an error before it reaches the API.
class HttpError extends Error {
	constructor(code, message) {
		super(message);
		this.code = code;
	}
}

function badRequest(detail) {
	return new HttpError(400, 'Bad Request (' + detail + ')');
}

// Whether an object has a key, at any depth, that could be mistaken
// for a part of the object machinery by code that copies objects.
function hasDangerousName(x) {
	if (! (x && (typeof(x) === 'object'))) {
		return false;
	}
	for (let k of Object.keys(x)) {
		if (((! Array.isArray(x)) && DANGEROUS_NAMES.has(k)) || hasDangerousName(x[k])) {
			return true;
		}
	}
	return false;
}

// Parameters of a query string or a form body. A key that is repeated
// gets an array of its values.
function formParams(text) {
	let params = {};
	for (let [ k, v ] of new URLSearchParams(text)) {
		if (DANGEROUS_NAMES.has(k)) {
			throw badRequest('Parameter name not allowed.');
		}
		if (! Object.hasOwn(params, k)) {
			params[k] = v;
		} else if (Array.isArray(params[k])) {
			params[k].push(v);
		} else {
			params[k] = [ params[k], v ];
		}
	}
	return params;
}

class ControlServer extends EventEmitter {

	#server;
	#where;
	#api;
	#debug;
	#maxBodySize;
	#closed;
	#started;

	// config.path         the socket file (required)
	// config.mode         the permissions of the socket file, a number or
	//                     an octal string (default 0600)
	// config.api          the API core to serve, or
	// config.nameDB       the database, for a core of its own
	// config.maxBodySize  the largest request body in bytes (65536)
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		if (! ((typeof(config?.path) === 'string') && (config.path !== ''))) {
			throw new Error('Invalid control socket path');
		}
		this.#where = { path: config.path, mode: listener.parseMode(config?.mode, 0o600) };
		this.#maxBodySize = config?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;
		if (! (Number.isSafeInteger(this.#maxBodySize) && (this.#maxBodySize >= 0))) {
			throw new Error('Invalid maximum body size');
		}
		if (! nullish(config?.api)) {
			if (! (config.api instanceof ApiCore)) {
				throw new Error('Invalid ApiCore');
			}
			this.#api = config.api;
		} else {
			this.#api = new ApiCore({ nameDB: config?.nameDB, nameServer: config?.nameServer, dohServer: config?.dohServer, debug: this.#debug });
		}
		this.#closed = false;
		this.#server = http.createServer(function(req, res) { this.#request(req, res); }.bind(this));
		// What cannot even be read as HTTP is answered in the envelope
		// of the API too.
		this.#server.on('clientError', function(e, socket) {
			if (! socket.writable) {
				socket.destroy();
				return;
			}
			let body = JSON.stringify({ status: 'error', code: 400, message: 'Bad Request' });
			socket.end('HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\n' +
					   'Content-Length: ' + Buffer.byteLength(body) + '\r\nConnection: close\r\n\r\n' + body);
		});
		this.#server.headersTimeout = BODY_READ_TIMEOUT_MS;
		this.#server.requestTimeout = BODY_READ_TIMEOUT_MS + 1000;
		this.#started = listener.listen(this.#server, this.#where)
			.then(function() {
				if (this.#closed) {
					return listener.close(this.#server, this.#where);
				}
				if (this.#debug) {
					log.debug('ControlServer:', this.#where.path);
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

	// Stops listening and removes the socket file. Returns a promise.
	async close() {
		this.#closed = true;
		await this.#started;
		await listener.close(this.#server, this.#where);
	}

	#send(res, status, body) {
		if (res.headersSent || res.writableEnded) {
			return;
		}
		res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8',
								'X-Content-Type-Options': 'nosniff',
								'Cache-Control': 'no-store' });
		res.end(this.#debug ? (JSON.stringify(body, null, 2) + "\n") : JSON.stringify(body));
	}

	#request(req, res) {
		this.#api.countCall();
		this.#parse(req)
			.then(function(request) {
				let result = this.#api.handle(request);
				this.#send(res, result.status, result.body);
			}.bind(this))
			.catch(function(e) {
				let code = (e instanceof HttpError) ? e.code : 500;
				if (code === 500) {
					log.error('ControlServer:', e);
				}
				// After an error the rest of the request is of no interest.
				res.setHeader('Connection', 'close');
				this.#send(res, code, { status: 'error', code: code, message: (code === 500) ? 'Internal Server Error' : e.message });
			}.bind(this));
	}

	// The body of a request as a buffer.
	#body(req) {
		return new Promise(function(resolve, reject) {
			let chunks = [];
			let size = 0;
			let timer = setTimeout(function() { reject(new HttpError(408, 'Request Timeout')); }, BODY_READ_TIMEOUT_MS);
			req.on('data', function(d) {
				size += d.length;
				if (size > this.#maxBodySize) {
					clearTimeout(timer);
					reject(new HttpError(413, 'Payload Too Large'));
					return;
				}
				chunks.push(d);
			}.bind(this));
			req.on('end', function() {
				clearTimeout(timer);
				resolve(Buffer.concat(chunks));
			});
			req.on('error', function() {
				clearTimeout(timer);
				reject(badRequest('Error occured while reading the request data.'));
			});
		}.bind(this));
	}

	// Turns an HTTP request into a request for the API core, by the
	// rules that the API has on its TCP port as well.
	async #parse(req) {
		if (! [ 'GET', 'POST', 'PUT', 'DELETE' ].includes(req.method)) {
			throw new HttpError(405, 'Method Not Allowed');
		}
		let url = req.url ?? '';
		let q = url.indexOf('?');
		let path = (q < 0) ? url : url.slice(0, q);
		let query = (q < 0) ? undefined : url.slice(q + 1);
		if (! path.startsWith('/')) {
			throw badRequest('Invalid request path.');
		}
		if ((path !== '/') && path.slice(1).replace(/\/$/, '').split('/').some((s) => [ '', '.', '..' ].includes(s))) {
			throw badRequest('Dangerous path.');
		}
		let body = await this.#body(req);
		let params;
		if ((req.method === 'GET') || (req.method === 'DELETE')) {
			if (body.length > 0) {
				throw badRequest('Empty body required for ' + req.method + ' requests.');
			}
			params = formParams(query ?? '');
		} else {
			if (query !== undefined) {
				throw badRequest('URL for POST or PUT must not contain query parameters.');
			}
			let m = (req.headers['content-type'] ?? '').match(/^\s*([^\s;]+)\s*(?:;\s*(.*\S))?\s*$/);
			let type = m ? m[1].toLowerCase() : undefined;
			if (type === 'application/json') {
				if (m[2] && (m[2].toLowerCase() !== 'charset=utf-8')) {
					throw badRequest('Bad charset for JSON content type.');
				}
				try {
					params = JSON.parse(body.toString('utf8'));
				} catch (e) {
					params = undefined;
				}
				if (! (params && (typeof(params) === 'object') && (! Array.isArray(params)))) {
					throw badRequest('Unable to parse JSON query parameters.');
				}
				if (hasDangerousName(params)) {
					throw badRequest('Parameter name not allowed.');
				}
			} else if ((type === 'application/x-www-form-urlencoded') || (type === 'application/www-form-urlencoded')) {
				params = formParams(body.toString('utf8'));
			} else {
				throw badRequest('POST or PUT body must be in JSON or www-form-urlencoded format.');
			}
		}
		return { method: req.method, path: path, params: params };
	}

}

module.exports = ControlServer;
