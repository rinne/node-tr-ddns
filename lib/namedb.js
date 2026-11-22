'use strict'

const EventEmitter = require('node:events');
const { Packet } = require('dns2');

const nullish = require('./nullish');
const log = require('./log');
const records = require('./records');

// The longest delay setTimeout() accepts.
const MAX_TIMER_MS = 2147483647;

// What a domain uses when nothing else has been set for it. The name
// servers default to the domain itself and the administrator to
// postmaster at the domain.
const DOMAIN_DEFAULTS = { ttl: 60, refresh: 300, retry: 3, expiration: 10, minimum: 10 };

const DOMAIN_NUMBERS = Object.keys(DOMAIN_DEFAULTS);

// The most name servers a domain can have.
const MAX_NS = 13;

// How many aliases are followed when answering for a CNAME.
const MAX_CNAME_CHAIN = 8;

const TYPE_DS = 43;

class NameDB extends EventEmitter {

	#hosts;
	#domains;
	#debug;
	#stat;
	#serialTimer;
	#expiryTimer;
	#nextExpiry;
	#ents;

	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		this.#stat = { lookup: { total: 0, errors: 0 } };
		this.#hosts = new Map();
		this.#domains = new Map();
		// Names that have no records of their own but have hosts below
		// them, with the number of such hosts. They exist, so a query
		// for one is answered with no data instead of no such name.
		this.#ents = new Map();
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

	// Checks the settings of a domain in options and returns them in
	// stored form on top of base. A setting that is null or an empty
	// string is removed, which brings back its default. Throws an Error
	// for a setting that is not acceptable.
	#domainSettings(options, base) {
		let rv = Object.assign({}, base);
		let reset = (v) => ((v === null) || (v === ''));
		if (options?.ns !== undefined) {
			if (reset(options.ns)) {
				delete rv.ns;
			} else {
				let list = Array.isArray(options.ns) ? options.ns : [ options.ns ];
				let ns = [];
				for (let x of list) {
					let n = records.normalize('ns', x);
					if (n === undefined) {
						throw new Error('Invalid domain setting (ns)');
					}
					if (! ns.includes(n)) {
						ns.push(n);
					}
				}
				if ((ns.length < 1) || (ns.length > MAX_NS)) {
					throw new Error('Invalid domain setting (ns)');
				}
				rv.ns = ns;
			}
		}
		if (options?.admin !== undefined) {
			if (reset(options.admin)) {
				delete rv.admin;
			} else {
				// Either a mail address or the same in the form it has in
				// an SOA record, where the at sign is a dot.
				let admin = options.admin;
				if ((typeof(admin) === 'string') && /^[^@.]+@[^@]+$/.test(admin)) {
					admin = admin.replace('@', '.');
				}
				if (! records.validName(admin)) {
					throw new Error('Invalid domain setting (admin)');
				}
				rv.admin = records.canonicalName(admin);
			}
		}
		for (let k of DOMAIN_NUMBERS) {
			if (options?.[k] === undefined) {
				continue;
			}
			if (reset(options[k])) {
				delete rv[k];
			} else if (Number.isSafeInteger(options[k]) && (options[k] >= 0) && (options[k] <= 2147483647)) {
				rv[k] = options[k];
			} else {
				throw new Error('Invalid domain setting (' + k + ')');
			}
		}
		return rv;
	}

	// The settings of a domain with the defaults filled in.
	#effective(d) {
		let rv = { ns: d.settings.ns ?? [ d.lcname ], admin: d.settings.admin ?? ('postmaster.' + d.lcname) };
		for (let k of DOMAIN_NUMBERS) {
			rv[k] = d.settings[k] ?? DOMAIN_DEFAULTS[k];
		}
		return rv;
	}

	// Adds a domain to be served. The options are
	//
	//   serial      continue the SOA serial from a previously used value,
	//               such as one read from a saved configuration
	//   ns          the name servers of the domain, a name or an array
	//               of names (default: the domain itself)
	//   admin       the mail address of the administrator (default:
	//               postmaster at the domain)
	//   ttl         the time to live of the records in seconds (60)
	//   refresh, retry, expiration, minimum
	//               the timers of the SOA record (300, 3, 10, 10)
	addDomain(domain, options) {
		if (! this.validDomain(domain)) {
			throw new Error('Invalid domain');
		}
		domain = domain.endsWith('.') ? domain.slice(0, -1) : domain;
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
		let settings = this.#domainSettings(options, {});
		let serial;
		if (Number.isSafeInteger(options?.serial) && (options.serial >= 1) && (options.serial <= 4294967295)) {
			serial = this.#advanceSerial(options.serial);
		} else {
			serial = this.#serial();
		}
		this.#domains.set(lcdomain, { name: domain, lcname: lcdomain, serial, expires: null, settings } );
		this.emit('adddomain', lcdomain);
	}

	// Changes the settings of a served domain; see addDomain(). Only
	// the settings present in options are changed. Returns false if
	// the domain is not served, and throws for an invalid setting.
	setDomainOptions(domain, options) {
		if (! this.validDomain(domain)) {
			return false;
		}
		let d = this.#domains.get(records.canonicalName(domain));
		if (! d) {
			return false;
		}
		d.settings = this.#domainSettings(options, d.settings);
		this.#incrementSerial(d.lcname);
		this.emit('updatedomain', d.lcname);
		return true;
	}

	// A served domain with its settings in effect, or undefined.
	getDomain(domain) {
		if (! this.validDomain(domain)) {
			return undefined;
		}
		let d = this.#domains.get(records.canonicalName(domain));
		if (! d) {
			return undefined;
		}
		let e = this.#effective(d);
		e.ns = e.ns.slice();
		return Object.assign({ name: d.name, lcname: d.lcname, serial: d.serial }, e);
	}

	// The served domain that the name is in, or false.
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

	// The names between a host and the top of its domain, both
	// excluded, from the host upwards.
	#between(lcname, lcdomain) {
		let rv = [];
		let n = lcname;
		while (true) {
			let i = n.indexOf('.');
			if (i < 0) {
				break;
			}
			n = n.slice(i + 1);
			if ((n === lcdomain) || (n.length <= lcdomain.length)) {
				break;
			}
			rv.push(n);
		}
		return rv;
	}

	#putHost(h) {
		if (! this.#hosts.has(h.lcname)) {
			for (let n of this.#between(h.lcname, h.domain)) {
				this.#ents.set(n, (this.#ents.get(n) ?? 0) + 1);
			}
		}
		this.#hosts.set(h.lcname, h);
	}

	#deleteHost(h) {
		if (! this.#hosts.delete(h.lcname)) {
			return false;
		}
		for (let n of this.#between(h.lcname, h.domain)) {
			let c = (this.#ents.get(n) ?? 1) - 1;
			if (c > 0) {
				this.#ents.set(n, c);
			} else {
				this.#ents.delete(n);
			}
		}
		return true;
	}

	removeDomain(domain) {
		if (! (typeof(domain) === 'string')) {
			return false;
		}
		let lcdomain = records.canonicalName(domain);
		if (! this.#domains.has(lcdomain)) {
			return false;
		}
		for (let h of Array.from(this.#hosts.values())) {
			if (h.domain === lcdomain) {
				this.#deleteHost(h);
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
				log.debug('Host name is invalid');
			}
			return false;
		}
		name = name.endsWith('.') ? name.slice(0, -1) : name;
		let lcname = name.toLowerCase();
		let d = this.#searchDomain(lcname);
		if (d === false) {
			if (this.#debug) {
				log.debug('Host name is outside of accepted domains');
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
			if (values.size > (records.TYPES[type].max ?? records.MAX_VALUES)) {
				return false;
			}
			n.data[type] = values;
		}
		// An alias cannot have other records, and the top of a domain
		// can be neither an alias nor delegated elsewhere.
		if ((n.data.cname.size > 0) &&
			((lcname === d.lcname) || records.NAMES.some((t) => ((t !== 'cname') && (n.data[t].size > 0))))) {
			return false;
		}
		if ((n.data.ns.size > 0) && (lcname === d.lcname)) {
			return false;
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
		this.#putHost(n);
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
		for (let [ lcname, h ] of Array.from(this.#hosts.entries())) {
			if (h.expires === null) {
				continue;
			}
			if (h.expires <= now) {
				if (this.#debug) {
					log.debug('ttl exceeded:', lcname);
				}
				this.#deleteHost(h);
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
		let lcname = records.canonicalName(name);
		let h = this.#hosts.get(lcname);
		if (! h) {
			return false;
		}
		this.#incrementSerial(h.domain);
		let rv = this.#deleteHost(h);
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
		let h = this.#hosts.get(records.canonicalName(name));
		if (! h) {
			return undefined;
		}
		return h.expires ?? null;
	}

	getHostData(name) {
		if (! this.valid(name)) {
			if (this.#debug) {
				log.debug('Host name is invalid in query');
			}
			return false;
		}
		let lcname = records.canonicalName(name);
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

	#soa(d, ttl) {
		let e = this.#effective(d);
		return { name: d.lcname,
				 type: Packet.TYPE.SOA,
				 'class': Packet.CLASS.IN,
				 ttl: ttl ?? e.ttl,
				 primary: e.ns[0],
				 admin: e.admin,
				 serial: d.serial,
				 refresh: e.refresh,
				 retry: e.retry,
				 expiration: e.expiration,
				 minimum: e.minimum };
	}

	// The records of one type that a name has. zone is the served
	// domain the name is in.
	#rrset(lcname, type, zone) {
		let e = this.#effective(zone);
		if (lcname === zone.lcname) {
			if (type === Packet.TYPE.SOA) {
				return [ this.#soa(zone) ];
			}
			if (type === Packet.TYPE.NS) {
				return records.answers('ns', e.ns, lcname, e.ttl);
			}
		}
		let rtype = records.BY_QTYPE.get(type);
		let h = this.#hosts.get(lcname);
		if ((rtype === undefined) || (! h) || (h.data[rtype].size < 1)) {
			return [];
		}
		return records.answers(rtype, h.data[rtype], lcname, e.ttl);
	}

	// Address records of the given names, for the additional section
	// of an answer that points to those names.
	#addresses(names) {
		let rv = [];
		for (let n of names) {
			let zone = this.#searchDomain(n);
			if (zone) {
				rv.push(...this.#rrset(n, Packet.TYPE.A, zone), ...this.#rrset(n, Packet.TYPE.AAAA, zone));
			}
		}
		return rv;
	}

	// The delegated host at or above lcname inside the zone, nearest
	// to the top of the zone, or null when lcname is not delegated.
	#delegation(lcname, zone) {
		let chain = this.#between(lcname, zone.lcname).reverse();
		if (lcname !== zone.lcname) {
			chain.push(lcname);
		}
		for (let n of chain) {
			let h = this.#hosts.get(n);
			if (h && (h.data.ns.size > 0)) {
				return h;
			}
		}
		return null;
	}

	// The lookup used by the name server. Returns false when the name
	// is not inside any served domain, which means that the query is
	// not answered at all. Otherwise returns
	//
	//   rcode        the DNS response code: 0 or 3 (no such name)
	//   aa           true for an authoritative answer, false for a
	//                referral to the name servers of a delegated name
	//   answers      the records that answer the question
	//   authorities  the SOA record of the domain when there is nothing
	//                to answer with, the name servers in a referral
	//   additionals  addresses of name servers mentioned
	lookup(name, type) {
		this.#stat.lookup.total++;
		if (! ((typeof(name) === 'string') && (name.length <= 254))) {
			this.#stat.lookup.errors++;
			return false;
		}
		let lcname = records.canonicalName(name);
		let zone = this.#searchDomain(lcname);
		if (! zone) {
			this.#stat.lookup.errors++;
			return false;
		}
		let e = this.#effective(zone);
		let negative = function(rcode) {
			// The SOA record tells how long the absence may be cached.
			return { rcode: rcode, aa: true, answers: [],
					 authorities: [ this.#soa(zone, Math.min(e.ttl, e.minimum)) ], additionals: [] };
		}.bind(this);
		if (! this.valid(name)) {
			// Not a name that could be stored here, but it is inside a
			// served domain, so the client gets an answer.
			return negative(Packet.RCODE.NXDOMAIN);
		}
		// A name that is delegated, or is below a delegated name, is
		// answered with a referral.
		let dh = this.#delegation(lcname, zone);
		if (dh) {
			if ((dh.lcname === lcname) && (type === TYPE_DS)) {
				// The parent side of a delegation answers for DS itself.
				return negative(Packet.RCODE.NOERROR);
			}
			return { rcode: Packet.RCODE.NOERROR, aa: false, answers: [],
					 authorities: records.answers('ns', dh.data.ns, dh.lcname, e.ttl),
					 additionals: this.#addresses(dh.data.ns) };
		}
		let answers = [];
		let current = lcname;
		let currentZone = zone;
		for (let i = 0; i <= MAX_CNAME_CHAIN; i++) {
			let h = this.#hosts.get(current);
			if ((type !== Packet.TYPE.CNAME) && h && (h.data.cname.size > 0)) {
				// An alias answers for every type. The records of the
				// target are added when the target is served here too.
				let ce = this.#effective(currentZone);
				answers.push(...records.answers('cname', h.data.cname, current, ce.ttl));
				current = Array.from(h.data.cname)[0];
				currentZone = this.#searchDomain(current);
				// Data below a delegation is not ours to give: the
				// client follows the alias itself and gets the referral.
				if ((! currentZone) || this.#delegation(current, currentZone)) {
					break;
				}
				continue;
			}
			answers.push(...this.#rrset(current, type, currentZone));
			break;
		}
		if (answers.length > 0) {
			let additionals = [];
			if ((type === Packet.TYPE.NS) && (lcname === zone.lcname)) {
				additionals = this.#addresses(e.ns);
			}
			return { rcode: Packet.RCODE.NOERROR, aa: true, answers: answers, authorities: [], additionals: additionals };
		}
		if ((lcname === zone.lcname) || this.#hosts.has(lcname) || this.#ents.has(lcname)) {
			return negative(Packet.RCODE.NOERROR);
		}
		return negative(Packet.RCODE.NXDOMAIN);
	}

	// The records of the given type that a name has, as an array, which
	// is empty when the name is inside a served domain but has no such
	// records. Returns false for an invalid name and for a name
	// outside the served domains. Unlike lookup(), this looks at the
	// name alone: aliases and delegations are not followed.
	get(name, type) {
		this.#stat.lookup.total++;
		if (! this.valid(name)) {
			if (this.#debug) {
				log.debug('Host name is invalid in query');
			}
			this.#stat.lookup.errors++;
			return false;
		}
		let lcname = records.canonicalName(name);
		let zone = this.#searchDomain(lcname);
		if (! zone) {
			this.#stat.lookup.errors++;
			return false;
		}
		return this.#rrset(lcname, type, zone);
	}

	flush() {
		this.#hosts.clear();
		this.#domains.clear();
		this.#ents.clear();
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
			// Only the settings that differ from the defaults are saved.
			let dd = Object.assign({ name: d.name, lcname: d.lcname, serial: d.serial, expires: d.expires }, d.settings);
			if (dd.ns) {
				dd.ns = dd.ns.slice();
			}
			domains.push(dd);
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
