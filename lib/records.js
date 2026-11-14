'use strict'

// The record types a host can have, and the rules for names. Everything
// that validates, normalises or encodes a record value goes through
// this table, whether the value comes from the API, from the
// configuration file or from a caller of the library.

const { Packet } = require('dns2');
const ipaddr = require('ipaddr.js');

// The most values of one type a single host can have.
const MAX_VALUES = 100;

// The longest TXT value in bytes.
const MAX_TXT_BYTES = 4096;

// A name has at least two labels of letters, digits and hyphens. A
// label does not start or end with a hyphen, is at most 63 characters
// long, and may start with an underscore, as service labels such as
// _acme-challenge, _domainkey and _tcp do. A dot at the end, which
// marks a fully qualified name, is accepted.
function validName(name) {
	if (! ((typeof(name) === 'string') && (name.length <= 254))) {
		return false;
	}
	if (name.endsWith('.')) {
		name = name.slice(0, -1);
	}
	if (name.length > 253) {
		return false;
	}
	let labels = name.split('.');
	if ((labels.length < 2) || (labels.length > 127)) {
		return false;
	}
	return labels.every((l) => ((l.length <= 63) && /^_?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(l)));
}

// The form of a name that is used as a key: lower case, without the
// dot at the end.
function canonicalName(name) {
	return (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();
}

function validDomain(domain) {
	return ((typeof(domain) === 'string') && validName('x.' + domain));
}

// A TXT value is sent as one or more character strings of at most 255
// bytes each. A value that fits is returned as it is, a longer one as
// an array of buffers.
function txtData(text) {
	let b = Buffer.from(text, 'utf8');
	if (b.length <= 255) {
		return text;
	}
	let parts = [];
	for (let i = 0; i < b.length; i += 255) {
		parts.push(b.subarray(i, i + 255));
	}
	return parts;
}

// Each type has
//   qtype      the DNS query type it answers
//   normalize  returns the stored form of a value, or undefined for
//              a value that is not acceptable
//   answers    turns the stored values into the type specific parts of
//              resource records
const TYPES = {

	a: {
		qtype: Packet.TYPE.A,
		normalize: function(v) {
			if (! ((typeof(v) === 'string') && ipaddr.IPv4.isValid(v))) {
				return undefined;
			}
			return ipaddr.IPv4.parse(v).toString();
		},
		answers: function(values) {
			return values.map((x) => ({ address: x }));
		}
	},

	aaaa: {
		qtype: Packet.TYPE.AAAA,
		normalize: function(v) {
			if (! ((typeof(v) === 'string') && ipaddr.IPv6.isValid(v))) {
				return undefined;
			}
			return ipaddr.IPv6.parse(v).toNormalizedString();
		},
		answers: function(values) {
			return values.map((x) => ({ address: x }));
		}
	},

	txt: {
		qtype: Packet.TYPE.TXT,
		normalize: function(v) {
			if (! ((typeof(v) === 'string') && (v !== '') && (Buffer.byteLength(v, 'utf8') <= MAX_TXT_BYTES))) {
				return undefined;
			}
			return v;
		},
		answers: function(values) {
			return values.map((x) => ({ data: txtData(x) }));
		}
	},

	// A mail server, optionally with a priority in front: "mail.example.com"
	// or "10 mail.example.com". A server without a priority gets its
	// position among the values of the host, starting from 1.
	mx: {
		qtype: Packet.TYPE.MX,
		normalize: function(v) {
			if (typeof(v) !== 'string') {
				return undefined;
			}
			let m = v.match(/^(?:(\d{1,5})\s+)?(\S+)$/);
			if (! (m && validName(m[2]))) {
				return undefined;
			}
			let host = canonicalName(m[2]);
			if (m[1] === undefined) {
				return host;
			}
			let prio = Number.parseInt(m[1]);
			if (prio > 65535) {
				return undefined;
			}
			return prio.toString() + ' ' + host;
		},
		answers: function(values) {
			let position = 1;
			return values.map(function(x) {
				let m = x.match(/^(\d+) (.*)$/);
				let rv = m ? { exchange: m[2], priority: Number.parseInt(m[1]) } : { exchange: x, priority: position };
				position++;
				return rv;
			});
		}
	},

	// An alias. A name that has a CNAME record has nothing else.
	cname: {
		qtype: Packet.TYPE.CNAME,
		max: 1,
		normalize: function(v) {
			if (! validName(v)) {
				return undefined;
			}
			return canonicalName(v);
		},
		answers: function(values) {
			return values.map((x) => ({ domain: x }));
		}
	},

	// A name server. On a host, NS records delegate the name and
	// everything under it to other servers.
	ns: {
		qtype: Packet.TYPE.NS,
		normalize: function(v) {
			if (! validName(v)) {
				return undefined;
			}
			return canonicalName(v);
		},
		answers: function(values) {
			return values.map((x) => ({ ns: x }));
		}
	},

	// "priority weight port target", for example "10 5 5060 sip.example.com".
	srv: {
		qtype: Packet.TYPE.SRV,
		normalize: function(v) {
			if (typeof(v) !== 'string') {
				return undefined;
			}
			let m = v.match(/^(\d{1,5})\s+(\d{1,5})\s+(\d{1,5})\s+(\S+)$/);
			if (! (m && validName(m[4]))) {
				return undefined;
			}
			let n = [ m[1], m[2], m[3] ].map((x) => Number.parseInt(x));
			if (n.some((x) => (x > 65535))) {
				return undefined;
			}
			return n.join(' ') + ' ' + canonicalName(m[4]);
		},
		answers: function(values) {
			return values.map(function(x) {
				let f = x.split(' ');
				return { priority: Number.parseInt(f[0]), weight: Number.parseInt(f[1]), port: Number.parseInt(f[2]), target: f[3] };
			});
		}
	},

	// "flags tag value", for example "0 issue letsencrypt.org". The
	// value may be enclosed in double quotes.
	caa: {
		qtype: Packet.TYPE.CAA,
		normalize: function(v) {
			if (typeof(v) !== 'string') {
				return undefined;
			}
			let m = v.match(/^(\d{1,3})\s+([a-zA-Z0-9]{1,15})\s+(.*)$/);
			if (! m) {
				return undefined;
			}
			let flags = Number.parseInt(m[1]);
			let value = m[3];
			if ((value.length >= 2) && value.startsWith('"') && value.endsWith('"')) {
				value = value.slice(1, -1);
			}
			if ((flags > 255) || (Buffer.byteLength(value, 'utf8') > 255) || /[\x00-\x1f\x7f]/.test(value)) {
				return undefined;
			}
			return flags.toString() + ' ' + m[2].toLowerCase() + ' ' + value;
		},
		answers: function(values) {
			return values.map(function(x) {
				let m = x.match(/^(\d+) (\S+) (.*)$/);
				return { flags: Number.parseInt(m[1]), tag: m[2], value: m[3] };
			});
		}
	}

};

const NAMES = Object.keys(TYPES);

const BY_QTYPE = new Map(NAMES.map((n) => [ TYPES[n].qtype, n ]));

function emptyData() {
	let d = {};
	for (let n of NAMES) {
		d[n] = new Set();
	}
	return d;
}

// Returns the stored form of a value of the given type, or undefined
// if the type is unknown or the value is not acceptable.
function normalize(type, value) {
	if (! Object.hasOwn(TYPES, type)) {
		return undefined;
	}
	return TYPES[type].normalize(value);
}

// Complete resource records of one type for a name.
function answers(type, values, name, ttl) {
	let t = TYPES[type];
	return t.answers(Array.from(values)).map((x) => Object.assign({ name: name, type: t.qtype, 'class': Packet.CLASS.IN, ttl: ttl }, x));
}

module.exports = {
	TYPES, NAMES, BY_QTYPE, MAX_VALUES, MAX_TXT_BYTES,
	validName, validDomain, canonicalName, txtData, emptyData, normalize, answers
};
