'use strict'

const EventEmitter = require('node:events');
const { Packet } = require('dns2');
const ipaddr = require('ipaddr.js');

class NameDB extends EventEmitter {

	#hosts;
	#domains;
	#debug;
	
	constructor(config) {
		super();
		this.#debug = config?.debug ? true : false;
		this.#hosts = new Map();
		this.#domains = new Map();
		setInterval(function() { this.#updateSerials()}.bind(this), 3600000);
	}

	#serial() {
		return (Math.floor((Date.now() / 15)) % 4294967295) + 1;
	}

	#updateSerials() {
		let ns = this.#serial();
		for (let dd of this.#domains.values()) {
			let os = dd.soa.serial;
			if ((ns > os) || ((os - ns) > 2147483648)) {
				dd.soa.serial = ns;
			}
		}
	}
	#incrementSerial(lcdomain) {
		let dd = this.#searchDomain(lcdomain);
		if (dd) {
			dd.soa.serial = (dd.soa.serial + 1) % 4294967296;
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
		let soa = {
			name: lcdomain,
			type: Packet.TYPE.SOA,
			class: Packet.CLASS.IN,
			ttl: 60,
			primary: lcdomain,
			admin: 'postmaster.' + lcdomain,
			serial: this.#serial(),
			refresh: 300,
			retry: 3,
			expiration: 10,
			minimum: 10
		};
		let mx = {
			name: lcdomain,
			type: Packet.TYPE.MX,
			class: Packet.CLASS.IN,
			ttl: 60,
			exchange: 'mail.' + lcdomain,
			priority: 1
		}
		this.#domains.set(lcdomain, { soa, mx } );
	}

	#searchDomain(lcname) {
		for (let [ k, v ] of this.#domains.entries()) {
			if ((k === lcname) || ((lcname.length > k.length) && ((lcname.slice(-1 - k.length)) === ('.' + k)))) {
				return v;
			}
		}
		return false;
	}

	removeDomain(domain) {
		if (! (typeof(domain) === 'string')) {
			return false;
		}
		lcdomain = domain.toLowerCase();
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
		return true;
	}

	set(name, data, ttlMs) {
		console.log('set:', name, data, ttlMs);
		if (! this.valid(name)) {
			return false;
		}
		let lcname = name.toLowerCase();
		let dd = this.#searchDomain(lcname);
		if (dd === false) {
			return false;
		}
		if (! (data && (typeof(data) === 'object'))) {
			return false;
		}
		let n = { name: name, domain: dd.soa.name, data: {}, timeout: null };
		if ((typeof(data?.a) === 'string') && (ipaddr.IPv4.isValid(data.a))) {
			n.data.a = data.a;
		} else if ((data?.a === undefined) || (data?.a === null) || (data?.a === '')) {
			n.data.a = null;
		} else {
			return false;
		}
		if ((typeof(data?.aaaa) === 'string') && (ipaddr.IPv6.isValid(data.aaaa))) {
			n.data.aaaa = ipaddr.IPv6.parse(data.aaaa).toNormalizedString();
		} else if ((data?.aaaa === undefined) || (data?.aaaa === null) || (data?.aaaa === '')) {
			n.data.aaaa = null;
		} else {
			return false;
		}
		if ((typeof(data?.txt) === 'string') && (data.txt !== '')) {
			n.data.txt = data.txt;
		} else if ((data?.txt === undefined) || (data?.txt === null) || (data?.txt === '')) {
			n.data.txt = null;
		} else {
			return false;
		}
		if (Number.isSafeInteger(ttlMs) && (ttlMs > 0) && (ttlMs <= 2147483647)) {
			n.timeout = setTimeout(function() { let d = this.#hosts.get(lcname);
												if (d) {
													d.timeout = null;
													this.#hosts.delete(lcname);
													this.emit('remove', lcname);
												}
											  }.bind(this),
								   ttlMs);
			n.expires = Date.now() + ttlMs;
		} else if ((ttlMs === undefined) || (ttlMs === null) || (ttlMs === 0)) {
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
		let n = this.#hosts.get(lcname);
		if (! n) {
			return false;
		}
		if (n.timeout) {
			clearTimeout(n.timeout);
			n.timeout = null;
		}
		this.#incrementSerial(n.domain);
		let rv = this.#hosts.delete(lcname);
		this.emit('remove', lcname);
		return rv;
	}

	get(name, type) {
		if (! this.valid(name)) {
			return false;
		}
		let lcname = name.toLowerCase();
		if (type === Packet.TYPE.SOA) {
			let d = this.#domains.get(lcname);
			if (d?.soa) {
				return d.soa;
			}
			return false;
		}
		if (type === Packet.TYPE.MX) {
			let d = this.#domains.get(lcname);
			if (d?.mx) {
				return d.mx;
			}
			return false;
		}
		let d = this.#hosts.get(lcname);
		switch (type) {
		case Packet.TYPE.A:
			if (d?.data?.a) {
				return {
					name: name,
					type: Packet.TYPE.A,
					class: Packet.CLASS.IN,
					ttl: 60,
					address: d.data.a
				};
			}
			return false;
		case Packet.TYPE.AAAA:
			if (d?.data?.aaaa) {
				return {
					name: name,
					type: Packet.TYPE.AAAA,
					class: Packet.CLASS.IN,
					ttl: 60,
					address: d.data.aaaa
				};
			}
			return false;
		case Packet.TYPE.TXT:
			if (d?.data?.txt) {
				return {
					name: name,
					type: Packet.TYPE.TXT,
					class: Packet.CLASS.IN,
					ttl: 60,
					data: d.data.txt
				};
			}
			return false;
		default:
			return false;
		}
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
	}

	valid(name) {
		return /^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$/.test(name);
	}

	validDomain(domain) {
		return ((typeof(domain) === 'string') && this.valid('x.' + domain));
	}

	dump() {

		let domains = [];
		let hosts = [];
		for (let d of this.#domains.values()) {
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
