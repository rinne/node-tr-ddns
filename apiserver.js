'use strict'

const EventEmitter = require('node:events');

const ipaddr = require('ipaddr.js');
const ApiSrv = require('tr-apisrv');

class ApiServer extends EventEmitter {

	#server;
	#debug;
	#db;
	
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
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
			console.log('ApiServer: TCP:', address + ':' + port.toString());
		}
	}

	async #authCb(r) {
		return true;
	}

	async #requestCb(r) {
		var res = r.res;
		delete r.res;
		switch (r.url) {
		case '/domain':
			return this.#domain(r);
		case '/host':
			return this.#host(r);
		case '/dump':
			return this.#dump(r);
		}
		if (opt.value('debug')) {
			console.log('API:', r.url, '(not found)');
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
					r.jsonResponse({ status: 'ok', code: 200, message: 'OK' }, 200);
				} catch  (e) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to add domain)' }, 400);
					return;
				}
			} else if ([ true, 'true' ].includes(r.params.remove)) {
				try {
					this.#db.removeDomain(r.params.domain);
					r.jsonResponse({ status: 'ok', code: 200, message: 'OK' }, 200);
				} catch  (e) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to remove domain)' }, 400);
					return;
				}
			} else {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (remove)' }, 400);
				return;
			}
			return;
		} catch (e) {
			console.error(e);
			r.jsonResponse({ status: 'error', code: 500, message: 'Internal error' }, 500);
		}
	}

	async #host(r) {
		try {
			if (! this.#db.valid(r.params.host)) {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (host)' }, 400);
				return;
			}
			let a, aaaa, txt, ttlMs, remove;
			if (r.params.a !== undefined) {
				if (! ipaddr.IPv4.isValid(r.params.a)) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (a)' }, 400);
					return;
				}
				a = r.params.a;
			} else {
				a = undefined;
			}
			if (r.params.aaaa !== undefined) {
				if (! ipaddr.IPv6.isValid(r.params.aaaa)) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (aaaa)' }, 400);
					return;
				}
				aaaa = r.params.aaaa;
			} else {
				aaaa = undefined;
			}
			if (r.params.txt !== undefined) {
				if (! (typeof(r.params.txt) === 'string')) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (txt)' }, 400);
					return;
				}
				txt = r.params.txt;
			}
			if (r.params.ttl !== undefined) {
				if (/^[1-9]\d{0,10}$/.test(r.params.ttl)) {
					ttlMs = Number.parseInt(r.params.ttl) * 1000;
				} else {
					ttlMs = r.params.ttl * 1000;
				}
				if (! (Number.isSafeInteger(ttlMs) && (ttlMs >= 1) && (ttlMs <= 2147483647))) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (ttl)' }, 400);
					return;
				}
			} else {
				ttlMs = undefined;
			}
			if (r.params.remove === undefined) {
				remove = (a || aaaa || txt) ? false : true;
			} else if ([ false, 'false' ].includes(r.params.remove)) {
				remove = false;
			} else if ([ true, 'true' ].includes(r.params.remove)) {
				remove = true;
			} else {
				r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (remove)' }, 400);
				return;
			}
			console.log(a, aaaa, txt, ttlMs, remove);
			if (remove) {
				if (a || aaaa || txt || ttlMs) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (conflicting params)' }, 400);
					return;
				}
				try {
					let rv = this.#db.remove(r.params.host);
					if (! rv) {
						throw new Error('Unable to remove host');
					}
					r.jsonResponse({ status: 'ok', code: 200, message: 'OK' }, 200);
				} catch (e) {
					r.jsonResponse({ status: 'error', code: 400, message: 'Bad request (unable to remove host)' }, 400);
					return;
				}
			} else {
				try {
					let rv = this.#db.set(r.params.host, { a, aaaa, txt }, ttlMs);
					if (! rv) {
						throw new Error('Unable to add host');
					}
					r.jsonResponse({ status: 'ok', code: 200, message: 'OK' }, 200);
				} catch (e) {
					console.log(e);
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

}

module.exports = ApiServer;
