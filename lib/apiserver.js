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
	#allowedHosts;

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
		// Host names that requests may be addressed to, besides
		// localhost and IP addresses.
		let hosts = config?.allowedHosts ?? [];
		if (typeof(hosts) === 'string') {
			hosts = hosts.split(',').map((x) => x.trim()).filter((x) => (x !== ''));
		}
		if (! (Array.isArray(hosts) && hosts.every((x) => ((typeof(x) === 'string') && /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(x))))) {
			throw new Error('Invalid allowed hosts');
		}
		this.#allowedHosts = new Set(hosts.map((x) => x.toLowerCase()));
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

	// The URL of a Host header, or of an Origin or Referer header, or
	// undefined when there is no header, or null when it is unusable.
	static #urlOf(v, full) {
		if (typeof(v) !== 'string') {
			return undefined;
		}
		try {
			return new URL(full ? v : ('http://' + v));
		} catch (e) {
			return null;
		}
	}

	// A web browser can be made to send requests to the API by any
	// page its user visits, even when the API listens on a loopback
	// address: a link or an image changes records with a GET. Such a
	// request is refused when the browser says that it comes from
	// another site (any other host or port), or when it is addressed
	// to a host name that the API does not go by (DNS rebinding).
	// Programs such as curl send none of these headers but Host.
	#foreign(r) {
		let h = r.headers ?? {};
		let target = ApiServer.#urlOf(h.host, false);
		if (target === null) {
			return true;
		}
		if (target !== undefined) {
			let name = target.hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1');
			if (! (ipaddr.isValid(name) || (name === 'localhost') || this.#allowedHosts.has(name))) {
				return true;
			}
		}
		let site = h['sec-fetch-site'];
		if ((site !== undefined) && (site !== 'same-origin') && (site !== 'none')) {
			return true;
		}
		for (let header of [ 'origin', 'referer' ]) {
			let from = ApiServer.#urlOf(h[header], true);
			if (from === undefined) {
				continue;
			}
			if ((from === null) || (target === undefined) || (from.host.toLowerCase() !== target.host.toLowerCase())) {
				return true;
			}
		}
		return false;
	}

	// Runs before the request body is parsed. The credentials are
	// compared as digests in constant time, so that the time taken
	// tells nothing about how much of a guess was right.
	async #authCb(r) {
		this.#api.countCall();
		if (this.#foreign(r)) {
			this.#api.countForeign();
			r.jsonResponse({ status: 'error', code: 403, message: 'Forbidden' }, 403);
			return false;
		}
		if (this.#basicAuthDigest === null) {
			return true;
		}
		let m, a = r.headers?.authorization;
		if ((typeof(a) === 'string') && (m = a.match(/^\s*Basic\s+([^\s]+)\s*$/i))) {
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
