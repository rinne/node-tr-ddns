'use strict'

const EventEmitter = require('node:events');

const ipaddr = require('ipaddr.js');
const ApiSrv = require('tr-apisrv');

const packageJson = require('./package.json');
const nullish = require('./nullish');
const log = require('./log');

class ApiServer extends EventEmitter {

	#server;
	#debug;
	#db;
	#stat;
	
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#stat = { apiCalls: 0 };
		let port = config?.port ?? 80;
		let address = config?.address ?? '0.0.0.0';
		if (! ipaddr.isValid(address)) {
			throw new Error('Invalid TCP listen address');
		}
		if (! (Number.isSafeInteger(port) && (port >= 0x0001) && (port <= 0xffff))) {
			throw new Error('Invalid TCP listen port');
		}
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		this.#db = config.nameDB;
		this.#server = new ApiSrv({ port: port,
									address: address,
									callback: async function(r) { return this.#requestCb(r); }.bind(this),
									authCallback: async function(r) { return this.#authCb(r); }.bind(this),
									prettyPrintJsonResponses: this.#debug,
									bodyReadTimeoutMs: 5000,
									debug: this.#debug });
		if (this.#debug) {
			log('ApiServer: TCP:', address + ':' + port.toString());
		}
	}

	async #authCb(r) {
		return true;
	}

	async #requestCb(r) {
		this.#stat.apiCalls++;
		var res = r.res;
		delete r.res;
		switch (r.url) {
		case '/':
			r.jsonResponse({ status: 'ok', code: 200, data: { package: packageJson?.name ?? '?', version: packageJson?.version ?? '?' } }, 200);
			return;
		case '/domain':
			return this.#domain(r);
		case '/host':
			return this.#host(r);
		case '/dump':
			return this.#dump(r);
		case '/stats':
			return this.#stats(r);
		case '/flush':
			return this.#flush(r);
		}
		if (this.#debug) {
			log('API:', r.url, '(not found)');
		}
		r.jsonResponse({ status: 'error', code: 404, message: 'Not found' }, 404);
	}

	async #domain(r) {
		try {
			if (! this.#db.validDomain(r.params.domain)) {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (domain)' }, 400);
				return;
			}
			if ([ undefined, false, 'false' ].includes(r.params.remove)) {
				try {
					this.#db.addDomain(r.params.domain);
					r.jsonResponse({ status: 'ok', code: 200 }, 200);
				} catch  (e) {
					if (this.#debug) {
						console.error(e);
					}
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to add domain)' }, 400);
					return;
				}
			} else if ([ true, 'true' ].includes(r.params.remove)) {
				try {
					this.#db.removeDomain(r.params.domain);
					r.jsonResponse({ status: 'ok', code: 200 }, 200);
				} catch  (e) {
					if (this.#debug) {
						console.error(e);
					}
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to remove domain)' }, 400);
					return;
				}
			} else {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (remove)' }, 400);
				return;
			}
			return;
		} catch (e) {
			if (this.#debug) {
				console.error(e);
			}
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	async #host(r) {
		try {
			if (! this.#db.valid(r.params.host)) {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (host)' }, 400);
				return;
			}
			let a, aaaa, txt, mx, ttlMs, remove, merge;
			if (nullish(r.params.a)) {
				a = undefined;
			} else {
				if (! (ipaddr.IPv4.isValid(r.params.a) || (r.params.a === ''))) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (a)' }, 400);
					return;
				}
				a = r.params.a;
			}
			if (nullish(r.params.aaaa)) {
				aaaa = undefined;
			} else {
				if (! (ipaddr.IPv6.isValid(r.params.aaaa) || (r.params.aaaa === ''))) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (aaaa)' }, 400);
					return;
				}
				aaaa = r.params.aaaa;
			}
			if (nullish(r.params.txt)) {
				txt = undefined;
			} else {
				if (! (typeof(r.params.txt) === 'string')) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (txt)' }, 400);
					return;
				}
				txt = r.params.txt;
			}
			if (nullish(r.params.mx)) {
				mx = undefined;
			} else {
				if (! (this.#db.valid(r.params.mx) || (r.params.mx === ''))) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (mx)' }, 400);
					return;
				}
				mx = r.params.mx;
			}
			if (nullish(r.params.ttl)) {
				ttlMs = undefined;
			} else {
				if (/^[1-9]\d{0,10}$/.test(r.params.ttl)) {
					ttlMs = Number.parseInt(r.params.ttl) * 1000;
				} else {
					ttlMs = r.params.ttl * 1000;
				}
				if (! (Number.isSafeInteger(ttlMs) && (ttlMs >= 1) && (ttlMs <= 2147483647))) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (ttl)' }, 400);
					return;
				}
			}
			if (nullish(r.params.remove)) {
				remove = ((typeof(a) === 'string') || (typeof(aaaa) === 'string') || (typeof(txt) === 'string') || (typeof(mx) === 'string')) ? false : true;
			} else if ([ false, 'false' ].includes(r.params.remove)) {
				remove = false;
			} else if ([ true, 'true' ].includes(r.params.remove)) {
				remove = true;
			} else {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (remove)' }, 400);
				return;
			}
			if ([ undefined, null, false, 'false' ].includes(r.params.merge)) {
				merge = false;
			} else if ([ true, 'true' ].includes(r.params.merge)) {
				merge = true;
			} else {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (merge)' }, 400);
				return;
			}
			if (remove) {
				if (a || aaaa || (typeof(txt) === 'string') || ttlMs) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (conflicting params)' }, 400);
					return;
				}
				try {
					let rv = this.#db.remove(r.params.host);
					if (! rv) {
						throw new Error('Unable to remove host');
					}
					r.jsonResponse({ status: 'ok', code: 200 }, 200);
				} catch (e) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to remove host)' }, 400);
					return;
				}
			} else {
				try {
					let rv = this.#db.set(r.params.host, { a, aaaa, txt, mx }, ttlMs, merge);
					if (! rv) {
						throw new Error('Unable to add host');
					}
					r.jsonResponse({ status: 'ok', code: 200 }, 200);
				} catch (e) {
					log(e);
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to add/update host)' }, 400);
					return;
				}
			}
			return;
		} catch (e) {
			console.error(e);
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	async #dump(r) {
		try {
			let d = this.#db.dump();
			r.jsonResponse({ status: 'ok', code: 200, data: d }, 200);
		} catch (e) {
			console.error(e);
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	async #stats(r) {
		try {
			let d = Object.assign({}, this.#db.stats(), this.#stat);
			r.jsonResponse({ status: 'ok', code: 200, data: d }, 200);
		} catch (e) {
			console.error(e);
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	async #flush(r) {
		try {
			this.#db.flush();
			r.jsonResponse({ status: 'ok', code: 200 }, 200);
		} catch (e) {
			console.error(e);
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}

	}

}

module.exports = ApiServer;
