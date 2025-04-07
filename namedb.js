'use strict'

const EventEmitter = require('node:events');
const { Packet } = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');

class NameDB extends EventEmitter {

	#hosts;
	#domains;
	#debug;
	#stat;
	
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#stat = { lookup: { total: 0, errors: 0 } };
		this.#hosts = new Map();
		this.#domains = new Map();
		setInterval(function() { this.#updateSerials()}.bind(this), 3600000);
	}

	#serial() {
		return (Math.floor((Date.now() / 15)) % 4294967295) + 1;
	}

	#updateSerials() {
		let ns = this.#serial();
		for (let d of this.#domains.values()) {
			let os = d.serial;
			if ((ns > os) || ((os - ns) > 2147483648)) {
				d.serial = ns;
			}
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

	addDomain(domain) {
		if (! this.validDomain(domain)) {
			throw new Error('Invalid domain');
		}
		let lcdomain = domain.toLowerCase();
		for (let k of this.#domains.keys()) {
			if (k === lcdomain) {
				let msg = 'Domain ' + lcdomain + 'is already included';
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
		let serial = this.#serial();
		this.#domains.set(lcdomain, { name: domain, lcname: lcdomain, serial, timeout: null, expires: null } );
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
				if (n[1].timeout) {
					clearTimeout(n[1].timeout);
					n[1].timeout = null;
				}
				this.#hosts.delete(n[0]);
			}
		}
		this.#domains.delete(lcdomain);
		this.emit('removedomain', lcdomain);
		return true;
	}

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
		let n = { name: name, lcname: lcname, domain: d.lcname, data: {}, timeout: null };
		let deleteA = false;
		if ((typeof(data?.a) === 'string') && (ipaddr.IPv4.isValid(data.a))) {
			n.data.a = data.a;
		} else if (data?.a === '') {
			deleteA = true;
			n.data.a = null;
		} else if (nullish(data?.a)) {
			n.data.a = null;
		} else {
			return false;
		}
		let deleteAAAA = false;
		if ((typeof(data?.aaaa) === 'string') && (ipaddr.IPv6.isValid(data.aaaa))) {
			n.data.aaaa = ipaddr.IPv6.parse(data.aaaa).toNormalizedString();
		} else if (data?.aaaa === '') {
			deleteAAAA = true;
			n.data.aaaa = null;
		} else if (nullish(data?.aaaa)) {
			n.data.aaaa = null;
		} else {
			return false;
		}
		let deleteTXT = false;
		if ((typeof(data?.txt) === 'string') && (data.txt !== '')) {
			n.data.txt = data.txt;
		} else if (data?.txt === '') {
			deleteTXT = true;
			n.data.txt = null;
		} else if (nullish(data?.txt)) {
			n.data.txt = null;
		} else {
			return false;
		}
		let deleteMX = false;
		if (this.valid(data?.mx) && (data.mx !== '')) {
			n.data.mx = data.mx;
		} else if (data?.mx === '') {
			deleteMX = true;
			n.data.mx = null;
		} else if (nullish(data?.mx)) {
			n.data.mx = null;
		} else {
			return false;
		}
		if (Number.isSafeInteger(ttlMs) && (ttlMs > 0) && (ttlMs <= 2147483647)) {
			n.timeout = setTimeout(function() { let d = this.#hosts.get(lcname);
												if (this.#debug) {
													log('ttl exceeded:', lcname);
												}
												if (d) {
													d.timeout = null;
													this.#hosts.delete(lcname);
													this.emit('remove', lcname);
												}
											  }.bind(this),
								   ttlMs);
			n.expires = Date.now() + ttlMs;
		} else if (nullish(ttlMs) || (ttlMs === 0)) {
			n.timeout = null;
			n.expires = null;
		} else {
			return false;
		}
		let o = this.#hosts.get(lcname);
		if (o) {
			if (o.timeout) {
				clearTimeout(o.timeout);
				o.timeout = null;
			}
			if (merge) {
				if (nullish(n.data.a) && (! nullish(o.data.a)) && (! deleteA)) {
					n.data.a = o.data.a;
				}
				if (nullish(n.data.aaaa) && (! nullish(o.data.aaaa)) && (! deleteAAAA)) {
					n.data.aaaa = o.data.aaaa;
				}
				if (nullish(n.data.txt) && (! nullish(o.data.txt)) && (! deleteTXT)) {
					n.data.txt = o.data.txt;
				}
				if (nullish(n.data.mx) && (! nullish(o.data.mx)) && (! deleteMX)) {
					n.data.mx = o.data.mx;
				}
			}
		}
		this.#incrementSerial(n.domain);
		this.#hosts.set(lcname, n);
		this.emit(o ? 'update' : 'add', lcname);
		return true;
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
		if (h.timeout) {
			clearTimeout(h.timeout);
			h.timeout = null;
		}
		this.#incrementSerial(h.domain);
		let rv = this.#hosts.delete(lcname);
		this.emit('remove', lcname);
		return rv;
	}

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
		let lcdomain = null;
		if (d) {
			lcdomain = d.lcname;
		} else if (h) {
			lcdomain = h.domain;
		} else {
			let dd = this.#searchDomain(lcname);
			if (dd) {
				lcdomain = dd.lcname;
			}
		}
		let r = false;
		switch (type) {
		case Packet.TYPE.SOA:
			if (d?.name && Number.isSafeInteger(d?.serial)) {
				r = { name: lcname,
					  type: Packet.TYPE.SOA,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  primary: lcname,
					  admin: 'postmaster.' + lcname,
					  serial: d.serial,
					  refresh: 300,
					  retry: 3,
					  expiration: 10,
					  minimum: 10 };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.NS:
			if (d?.name) {
				r = { name: lcname,
					  type: Packet.TYPE.NS,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  ns: lcname };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.A:
			if (h?.data?.a) {
				r = { name: lcname,
					  type: Packet.TYPE.A,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  address: h.data.a };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.AAAA:
			if (h?.data?.aaaa) {
				r = { name: lcname,
					  type: Packet.TYPE.AAAA,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  address: h.data.aaaa };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.TXT:
			if (h?.data?.txt) {
				r = { name: lcname,
					  type: Packet.TYPE.TXT,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  data: h.data.txt };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.MX:
			if (h?.data?.mx) {
				r = { name: lcname,
					  type: Packet.TYPE.MX,
					  'class': Packet.CLASS.IN,
					  ttl: 60,
					  exchange: h.data.mx,
					  priority: 1 };
			} else if (lcdomain !== null) {
				r = null;
			}
			break;
		case Packet.TYPE.CNAME:
		case Packet.TYPE.PTR:
		case Packet.TYPE.SRV:
		case Packet.TYPE.MD:
		case Packet.TYPE.MF:
		case Packet.TYPE.MB:
		case Packet.TYPE.MG:
		case Packet.TYPE.MR:
		case Packet.TYPE.NULL:
		case Packet.TYPE.WKS:
		case Packet.TYPE.HINFO:
		case Packet.TYPE.MINFO:
		case Packet.TYPE.EDNS:
		case Packet.TYPE.SPF:
		case Packet.TYPE.AXFR:
		case Packet.TYPE.MAILB:
		case Packet.TYPE.MAILA:
		case Packet.TYPE.ANY:
		case Packet.TYPE.CAA:
			if (lcdomain !== null) {
				r = null;
			}
			break;
		}
		if (r === false) {
			this.#stat.lookup.errors++;
		}
		return r;
	}

	flush() {
		for (let n of this.#hosts.values()) {
			if (n.timeout) {
				clearTimeout(n.timeout);
				n.timeout = null;
			}
		}
		this.#hosts.clear();
		this.#domains.clear();
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
		return ((typeof(name) === 'string') &&
				(name.length <= 253) &&
				/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)){1,125}$/.test(name));
	}

	validDomain(domain) {
		return ((typeof(domain) === 'string') && this.valid('x.' + domain));
	}

	dump() {

		let domains = [];
		let hosts = [];
		for (let d of this.#domains.values()) {
			d = Object.assign({}, d);
			delete d.timeout;
			domains.push(d);
		}
		for (let h of this.#hosts.values()) {
			h = Object.assign({}, h);
			delete h.timeout;
			hosts.push(h);
		}
		return { hosts, domains };
	}

};

module.exports = NameDB;
