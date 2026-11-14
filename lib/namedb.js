'use strict'

const EventEmitter = require('node:events');
const { Packet } = require('dns2');

const nullish = require('./nullish');
const log = require('./log');
const records = require('./records');

// The longest delay setTimeout() accepts.
const MAX_TIMER_MS = 2147483647;

class NameDB extends EventEmitter {

	#hosts;
	#domains;
	#debug;
	#stat;
	#serialTimer;
	#expiryTimer;
	#nextExpiry;

	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#stat = { lookup: { total: 0, errors: 0 } };
		this.#hosts = new Map();
		this.#domains = new Map();
		this.#expiryTimer = null;
		this.#nextExpiry = null;
		this.#serialTimer = setInterval(function() { this.#updateSerials()}.bind(this), 3600000);
	}

	// Stops all timers so that the process can exit. The contents of
	// the database are left as they are, but hosts no longer expire.
	close() {
		if (this.#serialTimer) {
			clearInterval(this.#serialTimer);
			this.#serialTimer = null;
		}
		if (this.#expiryTimer) {
			clearTimeout(this.#expiryTimer);
			this.#expiryTimer = null;
		}
		this.#nextExpiry = null;
	}

	#serial() {
		return (Math.floor((Date.now() / 15)) % 4294967295) + 1;
	}

	// The serial to continue from when an earlier one is known. The
	// time based serial is taken when it is ahead of the old one in
	// serial number arithmetic; otherwise the old one is kept, so that
	// a serial never goes backwards.
	#advanceSerial(os) {
		let ns = this.#serial();
		if ((ns > os) || ((os - ns) > 2147483648)) {
			return ns;
		}
		return os;
	}

	#updateSerials() {
		for (let d of this.#domains.values()) {
			d.serial = this.#advanceSerial(d.serial);
		}
	}

	#incrementSerial(lcdomain) {
		let d = this.#domains.get(lcdomain);
		if (d?.serial) {
			d.serial = (d.serial + 1) % 4294967296;
			if (d.serial == 0) {
				d.serial = 1;
			}
			return true;
		}
		return false;
	}

	// Adds a domain to be served. With options.serial the SOA serial
	// continues from a previously used value, such as one read from a
	// saved configuration.
	addDomain(domain, options) {
		if (! this.validDomain(domain)) {
			throw new Error('Invalid domain');
		}
		let lcdomain = domain.toLowerCase();
		for (let k of this.#domains.keys()) {
			if (k === lcdomain) {
				let msg = 'Domain ' + lcdomain + ' is already included';
				throw new Error(msg);
			}
			if ((k.length > lcdomain.length) && ((k.slice(-1 - lcdomain.length)) === ('.' + lcdomain))) {
				let msg = 'Already included domain ' + k + ' is a subdomain of ' + lcdomain;
				throw new Error(msg);
			}
			if ((lcdomain.length > k.length) && ((lcdomain.slice(-1 - k.length)) === ('.' + k))) {
				let msg = 'Domain ' + lcdomain + ' is a subdomain of already included domain ' + k;
				throw new Error(msg);
			}
		}
		let serial;
		if (Number.isSafeInteger(options?.serial) && (options.serial >= 1) && (options.serial <= 4294967295)) {
			serial = this.#advanceSerial(options.serial);
		} else {
			serial = this.#serial();
		}
		this.#domains.set(lcdomain, { name: domain, lcname: lcdomain, serial, expires: null } );
		this.emit('adddomain', lcdomain);
	}

	#searchDomain(lcname) {
		let components = lcname.split('.').reverse();
		if (components.length > 0) {
			let n = components.shift();
			while (true) {
				let d = this.#domains.get(n);
				if (d) {
					return d;
				}
				if (components.length < 1) {
					break;
				}
				n = components.shift() + '.' + n;
			}
		}
		return false;
	}

	removeDomain(domain) {
		if (! (typeof(domain) === 'string')) {
			return false;
		}
		let lcdomain = domain.toLowerCase();
		if (! this.#domains.has(lcdomain)) {
			return false;
		}
		for (let n of this.#hosts.entries()) {
			if (n[1].domain === lcdomain) {
				this.#hosts.delete(n[0]);
			}
		}
		this.#domains.delete(lcdomain);
		this.emit('removedomain', lcdomain);
		return true;
	}

	// Sets the records of a host. Each record type in data is a single
	// value, an array or a Set of values, an empty string (no values)
	// or absent. Without merge, the records given replace everything
	// the host had. With merge, a type that is absent is left as it
	// was, a single value is added to the existing ones, and an array,
	// a Set or an empty string replaces the values of that type.
	//
	// ttlMs is the lifetime of the host in milliseconds; without it
	// the host does not expire. Returns false, changing nothing, if
	// anything in the call is invalid.
	set(name, data, ttlMs, merge) {
		if (! this.valid(name)) {
			if (this.#debug) {
				log('Host name is invalid');
			}
			return false;
		}
		let lcname = name.toLowerCase();
		let d = this.#searchDomain(lcname);
		if (d === false) {
			if (this.#debug) {
				log('Host name is outside of accepted domains');
			}
			return false;
		}
		if (! (data && (typeof(data) === 'object'))) {
			return false;
		}
		let o = this.#hosts.get(lcname);
		let n = { name: name, lcname: lcname, domain: d.lcname, data: records.emptyData(), expires: null };
		for (let type of records.NAMES) {
			let v = data[type];
			let replace = false;
			let values = new Set();
			if (nullish(v)) {
				/*NOTHING*/
			} else if (v === '') {
				replace = true;
			} else if (typeof(v) === 'string') {
				let x = records.normalize(type, v);
				if (x === undefined) {
					return false;
				}
				values.add(x);
			} else if ((v instanceof Set) || Array.isArray(v)) {
				replace = true;
				for (let e of v) {
					let x = records.normalize(type, e);
					if (x === undefined) {
						return false;
					}
					values.add(x);
				}
			} else {
				return false;
			}
			if (merge && o && (! replace)) {
				for (let x of o.data[type]) {
					values.add(x);
				}
			}
			if (values.size > records.MAX_VALUES) {
				return false;
			}
			n.data[type] = values;
		}
		if (Number.isSafeInteger(ttlMs) && (ttlMs > 0)) {
			n.expires = Date.now() + ttlMs;
			if (! Number.isSafeInteger(n.expires)) {
				return false;
			}
		} else if (nullish(ttlMs) || (ttlMs === 0)) {
			n.expires = null;
		} else {
			return false;
		}
		this.#incrementSerial(n.domain);
		this.#hosts.set(lcname, n);
		if ((n.expires !== null) && ((this.#nextExpiry === null) || (n.expires < this.#nextExpiry))) {
			this.#scheduleExpiry(n.expires);
		}
		this.emit(o ? 'update' : 'add', lcname);
		return true;
	}

	// One timer serves all hosts: it is set to the earliest expiry
	// time. When it fires, every host that is due is removed and the
	// timer is set again for the next one.
	#scheduleExpiry(when) {
		if (this.#expiryTimer) {
			clearTimeout(this.#expiryTimer);
			this.#expiryTimer = null;
		}
		this.#nextExpiry = when;
		if (when === null) {
			return;
		}
		let delay = Math.min(Math.max(when - Date.now(), 0), MAX_TIMER_MS);
		this.#expiryTimer = setTimeout(function() {
			this.#expiryTimer = null;
			this.#expire();
		}.bind(this), delay);
	}

	#expire() {
		let now = Date.now();
		let next = null;
		for (let [ lcname, h ] of this.#hosts.entries()) {
			if (h.expires === null) {
				continue;
			}
			if (h.expires <= now) {
				if (this.#debug) {
					log('ttl exceeded:', lcname);
				}
				this.#hosts.delete(lcname);
				this.#incrementSerial(h.domain);
				this.emit('remove', lcname);
			} else if ((next === null) || (h.expires < next)) {
				next = h.expires;
			}
		}
		this.#scheduleExpiry(next);
	}

	remove(name) {
		if (! this.valid(name)) {
			return false;
		}
		let lcname = name.toLowerCase();
		let h = this.#hosts.get(lcname);
		if (! h) {
			return false;
		}
		this.#incrementSerial(h.domain);
		let rv = this.#hosts.delete(lcname);
		this.emit('remove', lcname);
		return rv;
	}

	// The time when the host expires as milliseconds since the epoch,
	// null for a host that does not expire, undefined when there is no
	// such host.
	getHostExpires(name) {
		if (! this.valid(name)) {
			return undefined;
		}
		let h = this.#hosts.get(name.toLowerCase());
		if (! h) {
			return undefined;
		}
		return h.expires ?? null;
	}

	getHostData(name) {
		if (! this.valid(name)) {
			if (this.#debug) {
				log('Host name is invalid in query');
			}
			return false;
		}
		let lcname = name.toLowerCase();
		if (! this.#searchDomain(lcname)) {
			return undefined;
		}
		let h = this.#hosts.get(lcname);
		if (! h) {
			return records.emptyData();
		}
		let d = {};
		for (let r of records.NAMES) {
			d[r] = new Set(h.data[r]);
		}
		return d;
	}

	// The lookup used by the name server. Returns false when the name
	// is not inside any served domain, which means that the query is
	// not answered at all. Otherwise returns { rcode, answers }, where
	// rcode is a DNS response code.
	lookup(name, type) {
		if ((typeof(name) === 'string') && (name.length <= 253) && (! this.valid(name))) {
			// Not a name that could be stored here, but if it is inside
			// a served domain, the client still gets an answer.
			if (this.#searchDomain(name.toLowerCase())) {
				this.#stat.lookup.total++;
				return { rcode: Packet.RCODE.NXDOMAIN, answers: [] };
			}
		}
		let answers = this.get(name, type);
		if (answers === false) {
			return false;
		}
		return { rcode: Packet.RCODE.NOERROR, answers: answers };
	}

	// The records of the given type for a name as an array, which is
	// empty when the name is inside a served domain but has no such
	// records. Returns false for an invalid name and for a name
	// outside the served domains.
	get(name, type) {
		this.#stat.lookup.total++;
		if (! this.valid(name)) {
			if (this.#debug) {
				log('Host name is invalid in query');
			}
			this.#stat.lookup.errors++;
			return false;
		}
		let lcname = name.toLowerCase();
		let d = this.#domains.get(lcname);
		let h = this.#hosts.get(lcname);
		if (! (d || h || this.#searchDomain(lcname))) {
			this.#stat.lookup.errors++;
			return false;
		}
		if (type === Packet.TYPE.SOA) {
			if (! d) {
				return [];
			}
			return [ { name: lcname,
					   type: Packet.TYPE.SOA,
					   'class': Packet.CLASS.IN,
					   ttl: 60,
					   primary: lcname,
					   admin: 'postmaster.' + lcname,
					   serial: d.serial,
					   refresh: 300,
					   retry: 3,
					   expiration: 10,
					   minimum: 10 } ];
		}
		if (type === Packet.TYPE.NS) {
			if (! d) {
				return [];
			}
			return [ { name: lcname,
					   type: Packet.TYPE.NS,
					   'class': Packet.CLASS.IN,
					   ttl: 60,
					   ns: lcname } ];
		}
		let rtype = records.BY_QTYPE.get(type);
		if ((rtype === undefined) || (! h) || (h.data[rtype].size < 1)) {
			// Either a type that has no data here or a name without
			// records of the type. A name inside a served domain gets
			// an empty answer whatever the type is.
			return [];
		}
		return records.answers(rtype, h.data[rtype], lcname, 60);
	}

	flush() {
		this.#hosts.clear();
		this.#domains.clear();
		this.#scheduleExpiry(null);
		this.emit('flush');
	}

	stats() {
		return {
			lookup: Object.assign({}, this.#stat.lookup),
			domains: this.#domains.size,
			hosts: this.#hosts.size
		};
	}

	valid(name) {
		return records.validName(name);
	}

	validDomain(domain) {
		return records.validDomain(domain);
	}

	dump() {
		let domains = [];
		let hosts = [];
		for (let d of this.#domains.values()) {
			domains.push(Object.assign({}, d));
		}
		for (let h of this.#hosts.values()) {
			let hh = Object.assign({}, h);
			hh.data = {};
			for (let r of records.NAMES) {
				hh.data[r] = Array.from(h.data[r]);
			}
			hosts.push(hh);
		}
		return { hosts, domains };
	}

};

module.exports = NameDB;
