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

function validName(name) {
	return ((typeof(name) === 'string') &&
			(name.length <= 253) &&
			/^(_?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)){1,125}$/.test(name));
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

	mx: {
		qtype: Packet.TYPE.MX,
		normalize: function(v) {
			if (! validName(v)) {
				return undefined;
			}
			return v.toLowerCase();
		},
		answers: function(values) {
			let prio = 1;
			return values.map((x) => ({ exchange: x, priority: prio++ }));
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
	validName, validDomain, txtData, emptyData, normalize, answers
};
