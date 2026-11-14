'use strict'

// The calls of the API, without any transport. A request is a method,
// a path and parameters; the result is a status and a body. The HTTP
// servers of the package are thin layers on top of this.

const packageJson = require('../package.json');
const nullish = require('./nullish');
const log = require('./log');
const records = require('./records');

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

class ApiCore {

	#debug;
	#db;
	#nameServer;
	#dohServer;
	#stat;

	// config.nameDB      the database to manage (required)
	// config.nameServer  adds its counters to /stats as dns
	// config.dohServer   adds its counters to /stats as doh
	constructor(config) {
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		for (let k of [ 'nameServer', 'dohServer' ]) {
			if (! (nullish(config?.[k]) || (typeof(config[k].stats) === 'function'))) {
				throw new Error('Invalid ' + ((k === 'nameServer') ? 'NameServer' : 'DohServer'));
			}
		}
		this.#db = config.nameDB;
		this.#nameServer = config?.nameServer ?? null;
		this.#dohServer = config?.dohServer ?? null;
		this.#stat = { apiCalls: 0, authFailures: 0 };
	}

	// The transports tell about the requests they receive and about
	// the ones they turn away for missing or wrong credentials.
	countCall() {
		this.#stat.apiCalls++;
	}

	countAuthFailure() {
		this.#stat.authFailures++;
	}

	// Performs one call. request.path is the path without a query
	// string and request.params an object of parameters. Returns
	// { status, body }, where body is the JSON object to send and
	// status the HTTP status, which is also in body.code. Never throws.
	handle(request) {
		let params = request?.params;
		if (! (params && (typeof(params) === 'object'))) {
			params = {};
		}
		let ok = function(data) {
			let body = { status: 'ok', code: 200 };
			if (data !== undefined) {
				body.data = data;
			}
			return { status: 200, body: body };
		};
		try {
			switch (request?.path) {
			case '/':
				return ok({ package: packageJson?.name ?? '?', version: packageJson?.version ?? '?' });
			case '/domain':
				this.#domain(params);
				return ok();
			case '/host':
				this.#host(params);
				return ok();
			case '/dump':
				return ok(this.#db.dump());
			case '/stats':
				return ok(this.#stats());
			case '/flush':
				this.#db.flush();
				return ok();
			case '/record':
				this.#record(params);
				return ok();
			}
			if (this.#debug) {
				log.debug('API:', request?.path, '(not found)');
			}
			return { status: 404, body: { status: 'error', code: 404, message: 'Not found' } };
		} catch (e) {
			if (e instanceof BadRequest) {
				return { status: 400, body: { status: 'error', code: 400, message: e.message } };
			}
			log.error('API:', request?.path, e);
			return { status: 500, body: { status: 'error', code: 500, message: 'Internal error' } };
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

	#domain(p) {
		let domain = p.domain;
		if (! this.#db.validDomain(domain)) {
			throw new BadRequest('domain');
		}
		let options = this.#domainOptions(p);
		let remove = booleanParam(p, 'remove') ?? false;
		let update = booleanParam(p, 'update') ?? false;
		// With ensure the call says what should be there, and it is not
		// an error if that is the case already: the domain is added if
		// it is not served, and the settings given are applied if it is.
		let ensure = booleanParam(p, 'ensure') ?? false;
		if (ensure && (update || remove)) {
			throw new BadRequest('conflicting params');
		}
		if (ensure && this.#db.getDomain(domain)) {
			if (! options) {
				// Served already and nothing to change.
				return;
			}
			update = true;
		}
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
					log.debug(e);
				}
				let m = e.message.match(/^Invalid domain setting \((.*)\)$/);
				throw new BadRequest(m ? m[1] : 'unable to add domain');
			}
		}
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

	#host(p) {
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
		// With ensure, removing a host that is not there is not an
		// error.
		let ensure = booleanParam(p, 'ensure') ?? false;
		if (ensure && (! remove)) {
			throw new BadRequest('conflicting params');
		}
		if (remove) {
			if (conflicting || ttlMs) {
				throw new BadRequest('conflicting params');
			}
			if (! (this.#db.remove(p.host) || (ensure && (this.#db.getHostData(p.host) !== undefined)))) {
				throw new BadRequest('unable to remove host');
			}
		} else if (! this.#db.set(p.host, data, ttlMs, merge)) {
			throw new BadRequest('unable to add/update host');
		}
	}

	#record(p) {
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
	}

	#stats() {
		let d = Object.assign({}, this.#db.stats(), this.#stat);
		if (this.#nameServer) {
			d.dns = this.#nameServer.stats();
		}
		if (this.#dohServer) {
			d.doh = this.#dohServer.stats();
		}
		return d;
	}

}

module.exports = ApiCore;
