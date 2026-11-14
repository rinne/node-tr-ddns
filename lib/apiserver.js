'use strict'

const EventEmitter = require('node:events');
const crypto = require('node:crypto');

const ipaddr = require('ipaddr.js');
const ApiSrv = require('tr-apisrv');

const nullish = require('./nullish');
const log = require('./log');
const ApiCore = require('./api');

// The largest request body accepted, in bytes.
const DEFAULT_MAX_BODY_SIZE = 65536;

class ApiServer extends EventEmitter {

	#server;
	#debug;
	#api;
	#basicAuthDigest;

	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		this.#basicAuthDigest = null;
		if (! nullish(config?.basicAuth)) {
			if (! ((typeof(config.basicAuth) === 'string') && (config.basicAuth !== ''))) {
				throw new Error('Invalid basic auth');
			}
			this.#basicAuthDigest = crypto.createHash('sha256').update(config.basicAuth, 'utf8').digest();
		}
		let port = config?.port ?? 80;
		let address = config?.address ?? '0.0.0.0';
		let maxBodySize = config?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;
		if (! ipaddr.isValid(address)) {
			throw new Error('Invalid TCP listen address');
		}
		if (! (Number.isSafeInteger(port) && (port >= 0x0001) && (port <= 0xffff))) {
			throw new Error('Invalid TCP listen port');
		}
		if (! (Number.isSafeInteger(maxBodySize) && (maxBodySize >= 0))) {
			throw new Error('Invalid maximum body size');
		}
		// The calls themselves are in the API core. One that is given
		// is shared with the other transports of the program.
		if (! nullish(config?.api)) {
			if (! (config.api instanceof ApiCore)) {
				throw new Error('Invalid ApiCore');
			}
			this.#api = config.api;
		} else {
			this.#api = new ApiCore({ nameDB: config?.nameDB, nameServer: config?.nameServer, dohServer: config?.dohServer, debug: this.#debug });
		}
		this.#server = new ApiSrv({ port: port,
									address: address,
									callback: async function(r) { return this.#requestCb(r); }.bind(this),
									authCallback: async function(r) { return this.#authCb(r); }.bind(this),
									errorCallback: function(e) { return this.#errorCb(e); }.bind(this),
									prettyPrintJsonResponses: this.#debug,
									bodyReadTimeoutMs: 5000,
									maxBodySize: maxBodySize,
									requireObjectBody: true,
									rejectDangerousParamNames: true,
									debug: this.#debug });
		// The HTTP layer ends the process when it cannot listen. That
		// decision belongs to the application, so the failure is
		// passed on as an event instead.
		let server = this.#server.server;
		server.removeAllListeners('error');
		server.on('error', function(e) { this.emit('error', e); }.bind(this));
		server.on('listening', function() { this.emit('ready'); }.bind(this));
		if (this.#debug) {
			log.debug('ApiServer: TCP:', address + ':' + port.toString());
		}
	}

	// Stops listening and drops open connections. Returns a promise
	// that resolves when the server has closed.
	close() {
		let server = this.#server?.server;
		if (! (server && server.listening)) {
			return Promise.resolve();
		}
		return new Promise(function(resolve) {
			server.close(function() { resolve(); });
			if (typeof(server.closeAllConnections) === 'function') {
				server.closeAllConnections();
			}
		});
	}

	// Errors that the HTTP layer generates itself (unsupported method,
	// unreadable body, timeout) are sent in the same envelope as the
	// errors of the API calls.
	#errorCb(e) {
		let res = e?.res;
		if ((! res) || res.headersSent || res.writableEnded) {
			return false;
		}
		let code = (Number.isSafeInteger(e.code) && (e.code >= 400) && (e.code <= 599)) ? e.code : 500;
		let body = { status: 'error', code: code, message: (typeof(e.message) === 'string') ? e.message : 'Error' };
		res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8',
							  'X-Content-Type-Options': 'nosniff',
							  'Cache-Control': 'no-store' });
		res.end(this.#debug ? (JSON.stringify(body, null, 2) + "\n") : JSON.stringify(body));
		return true;
	}

	// Runs before the request body is parsed. The credentials are
	// compared as digests in constant time, so that the time taken
	// tells nothing about how much of a guess was right.
	async #authCb(r) {
		this.#api.countCall();
		if (this.#basicAuthDigest === null) {
			return true;
		}
		let m, a = r.headers?.authorization;
		if ((typeof(a) === 'string') && (m = a.match(/^\s*Basic\s+([^\s]+)\s*$/))) {
			let digest = crypto.createHash('sha256').update(m[1], 'utf8').digest();
			if (crypto.timingSafeEqual(digest, this.#basicAuthDigest)) {
				return true;
			}
		}
		this.#api.countAuthFailure();
		r.res.setHeader('WWW-Authenticate', 'Basic realm="TR-DDNS", charset="UTF-8"');
		r.jsonResponse({ status: 'error', code: 401, message: 'Unauthorized' }, 401);
		return false;
	}

	async #requestCb(r) {
		let result = this.#api.handle({ method: r.method, path: r.url, params: r.params });
		return r.jsonResponse(result.body, result.status);
	}

}

module.exports = ApiServer;
