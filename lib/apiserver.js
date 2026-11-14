'use strict'

const EventEmitter = require('node:events');
const crypto = require('node:crypto');

const ipaddr = require('ipaddr.js');
const ApiSrv = require('tr-apisrv');

const packageJson = require('../package.json');
const nullish = require('./nullish');
const log = require('./log');
const records = require('./records');

// The largest request body accepted, in bytes.
const DEFAULT_MAX_BODY_SIZE = 65536;

// An error that is answered with 400 and the given detail.
class BadRequest extends Error {
	constructor(detail) {
		super('Bad request (' + detail + ')');
		this.detail = detail;
	}
}

// A parameter that is true or false, either as a JSON boolean or as
// the corresponding string. Returns undefined when absent.
function booleanParam(params, name) {
	let v = params[name];
	if (nullish(v)) {
		return undefined;
	}
	if ([ false, 'false' ].includes(v)) {
		return false;
	}
	if ([ true, 'true' ].includes(v)) {
		return true;
	}
	throw new BadRequest(name);
}

class ApiServer extends EventEmitter {

	#server;
	#debug;
	#db;
	#nameServer;
	#stat;
	#basicAuthDigest;

	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#stat = { apiCalls: 0, authFailures: 0 };
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
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		if (! (nullish(config?.nameServer) || (typeof(config.nameServer.stats) === 'function'))) {
			throw new Error('Invalid NameServer');
		}
		this.#db = config.nameDB;
		this.#nameServer = config?.nameServer ?? null;
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
			log('ApiServer: TCP:', address + ':' + port.toString());
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
		this.#stat.apiCalls++;
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
		this.#stat.authFailures++;
		r.res.setHeader('WWW-Authenticate', 'Basic realm="TR-DDNS", charset="UTF-8"');
		r.jsonResponse({ status: 'error', code: 401, message: 'Unauthorized' }, 401);
		return false;
	}

	async #requestCb(r) {
		try {
			switch (r.url) {
			case '/':
				return r.jsonResponse({ status: 'ok', code: 200, data: { package: packageJson?.name ?? '?', version: packageJson?.version ?? '?' } }, 200);
			case '/domain':
				return this.#domain(r);
			case '/host':
				return this.#host(r);
			case '/dump':
				return r.jsonResponse({ status: 'ok', code: 200, data: this.#db.dump() }, 200);
			case '/stats':
				return this.#stats(r);
			case '/flush':
				this.#db.flush();
				return r.jsonResponse({ status: 'ok', code: 200 }, 200);
			case '/record':
				return this.#record(r);
			}
			if (this.#debug) {
				log('API:', r.url, '(not found)');
			}
			return r.jsonResponse({ status: 'error', code: 404, message: 'Not found' }, 404);
		} catch (e) {
			if (e instanceof BadRequest) {
				return r.jsonResponse({ status: 'error', code: 400, message: e.message }, 400);
			}
			log('API:', r.url, e);
			return r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	// The settings of a domain from the parameters of a call. A number
	// may come as a string, and an empty string resets a setting to
	// its default.
	#domainOptions(p) {
		let options = {};
		let given = false;
		if (! nullish(p.ns)) {
			let list = Array.isArray(p.ns) ? p.ns : [ p.ns ];
			if (! ((p.ns === '') || ((list.length > 0) && list.every((x) => (records.normalize('ns', x) !== undefined))))) {
				throw new BadRequest('ns');
			}
			options.ns = p.ns;
			given = true;
		}
		if (! nullish(p.admin)) {
			if (typeof(p.admin) !== 'string') {
				throw new BadRequest('admin');
			}
			options.admin = p.admin;
			given = true;
		}
		for (let k of [ 'ttl', 'refresh', 'retry', 'expiration', 'minimum' ]) {
			let v = p[k];
			if (nullish(v)) {
				continue;
			}
			if (v === '') {
				options[k] = '';
			} else if ((typeof(v) === 'string') && /^\d{1,10}$/.test(v)) {
				options[k] = Number.parseInt(v);
			} else if (typeof(v) === 'number') {
				options[k] = v;
			} else {
				throw new BadRequest(k);
			}
			if ((options[k] !== '') && (! (Number.isSafeInteger(options[k]) && (options[k] >= 0) && (options[k] <= 2147483647)))) {
				throw new BadRequest(k);
			}
			given = true;
		}
		return given ? options : undefined;
	}

	#domain(r) {
		let p = r.params;
		let domain = p.domain;
		if (! this.#db.validDomain(domain)) {
			throw new BadRequest('domain');
		}
		let options = this.#domainOptions(p);
		let remove = booleanParam(p, 'remove') ?? false;
		let update = booleanParam(p, 'update') ?? false;
		if (remove) {
			if (options || update) {
				throw new BadRequest('conflicting params');
			}
			this.#db.removeDomain(domain);
		} else if (update) {
			// Changes the settings of a domain that is already served.
			let ok;
			try {
				ok = this.#db.setDomainOptions(domain, options ?? {});
			} catch (e) {
				throw new BadRequest(e.message.replace(/^.*\((.*)\)$/, '$1'));
			}
			if (! ok) {
				throw new BadRequest('unable to update domain');
			}
		} else {
			try {
				this.#db.addDomain(domain, options);
			} catch (e) {
				if (this.#debug) {
					log(e);
				}
				let m = e.message.match(/^Invalid domain setting \((.*)\)$/);
				throw new BadRequest(m ? m[1] : 'unable to add domain');
			}
		}
		return r.jsonResponse({ status: 'ok', code: 200 }, 200);
	}

	// A lifetime in seconds as milliseconds, or undefined when absent.
	#ttlParam(params) {
		let v = params.ttl;
		if (nullish(v)) {
			return undefined;
		}
		let ttlMs;
		if ((typeof(v) === 'string') && /^[1-9]\d{0,10}$/.test(v)) {
			ttlMs = Number.parseInt(v) * 1000;
		} else if (typeof(v) === 'number') {
			ttlMs = v * 1000;
		}
		if (! (Number.isSafeInteger(ttlMs) && (ttlMs >= 1))) {
			throw new BadRequest('ttl');
		}
		return ttlMs;
	}

	#host(r) {
		let p = r.params;
		if (! this.#db.valid(p.host)) {
			throw new BadRequest('host');
		}
		// Each record type is absent, an empty string (no values), a
		// single value, or several values as an array.
		let data = {};
		let given = false;
		let conflicting = false;
		for (let type of records.NAMES) {
			let v = p[type];
			if (nullish(v)) {
				continue;
			}
			if (Array.isArray(v)) {
				if ((v.length < 1) || (! v.every((x) => (records.normalize(type, x) !== undefined)))) {
					throw new BadRequest(type);
				}
			} else if (! ((v === '') || (records.normalize(type, v) !== undefined))) {
				throw new BadRequest(type);
			}
			data[type] = v;
			given = true;
			if ((v !== '') || (type === 'txt')) {
				conflicting = true;
			}
		}
		let ttlMs = this.#ttlParam(p);
		// Without an explicit remove parameter, a call that has no
		// records at all removes the host.
		let remove = booleanParam(p, 'remove') ?? (! given);
		let merge = booleanParam(p, 'merge') ?? false;
		if (remove) {
			if (conflicting || ttlMs) {
				throw new BadRequest('conflicting params');
			}
			if (! this.#db.remove(p.host)) {
				throw new BadRequest('unable to remove host');
			}
		} else if (! this.#db.set(p.host, data, ttlMs, merge)) {
			throw new BadRequest('unable to add/update host');
		}
		return r.jsonResponse({ status: 'ok', code: 200 }, 200);
	}

	#record(r) {
		let p = r.params;
		if (! this.#db.valid(p.host)) {
			throw new BadRequest('host');
		}
		if (! [ 'set', 'add', 'remove', 'clear' ].includes(p.command)) {
			throw new BadRequest('command');
		}
		if (! ((typeof(p.type) === 'string') && records.NAMES.includes(p.type))) {
			throw new BadRequest('type');
		}
		let d = this.#db.getHostData(p.host);
		if (! d) {
			throw new BadRequest('no matching domain');
		}
		if (p.command === 'clear') {
			d[p.type] = new Set();
		} else {
			let value = records.normalize(p.type, p.value);
			if (value === undefined) {
				throw new BadRequest('value');
			}
			switch (p.command) {
			case 'set':
				d[p.type] = new Set([ value ]);
				break;
			case 'add':
				d[p.type].add(value);
				break;
			case 'remove':
				d[p.type].delete(value);
				break;
			}
		}
		// The lifetime of the host is not changed by this call.
		let ttlMs;
		let expires = this.#db.getHostExpires(p.host);
		if (Number.isFinite(expires)) {
			ttlMs = Math.max(1, expires - Date.now());
		}
		if (! this.#db.set(p.host, d, ttlMs)) {
			throw new BadRequest('unable to add/update host');
		}
		return r.jsonResponse({ status: 'ok', code: 200 }, 200);
	}

	#stats(r) {
		let d = Object.assign({}, this.#db.stats(), this.#stat);
		if (this.#nameServer) {
			d.dns = this.#nameServer.stats();
		}
		return r.jsonResponse({ status: 'ok', code: 200, data: d }, 200);
	}

}

module.exports = ApiServer;
