'use strict'

// Answering DNS queries, without any transport. A parsed query and the
// address it came from go in; a response packet, or the reason why
// there is none, comes out. The servers for UDP, TCP and HTTP are thin
// layers on top of this, and share the rate limit and the counters
// when they share a core.

const dns2 = require('dns2');
const ipaddr = require('ipaddr.js');

const nullish = require('./nullish');
const log = require('./log');

// The UDP payload size offered to clients that use EDNS. It avoids
// fragmentation on practically every path.
const EDNS_UDP_PAYLOAD_SIZE = 1232;

// The length of the period that the rate limit counts over.
const RATE_PERIOD_MS = 1000;

class DnsCore {

	#debug;
	#db;
	#stat;
	#rateLimit;
	#rateCounts;
	#rateStart;
	#refuse;

	// The default limit of queries per second from one source.
	static DEFAULT_RATE_LIMIT = 500;

	// config.nameDB           the database to answer from (required)
	// config.rateLimit        queries per second answered to one source,
	//                         0 for no limit (default 500)
	// config.refuseOutOfZone  answer REFUSED to queries for names outside
	//                         the served domains instead of nothing
	constructor(config) {
		this.#debug = config?.debug ? true : false;
		if (this.#debug) {
			log.enableDebug();
		}
		if (! (typeof(config?.nameDB?.get) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		this.#db = config.nameDB;
		this.#refuse = config?.refuseOutOfZone ? true : false;
		this.#stat = { queries: 0, answered: 0, nxdomain: 0, empty: 0, refused: 0,
					   dropped: { notQuery: 0, invalid: 0, outOfZone: 0, rateLimited: 0, error: 0 } };
		if (nullish(config?.rateLimit)) {
			this.#rateLimit = DnsCore.DEFAULT_RATE_LIMIT;
		} else if ((config.rateLimit === 0) || (config.rateLimit === false)) {
			this.#rateLimit = 0;
		} else if (Number.isSafeInteger(config.rateLimit) && (config.rateLimit > 0)) {
			this.#rateLimit = config.rateLimit;
		} else {
			throw new Error('Invalid rate limit');
		}
		this.#rateCounts = new Map();
		this.#rateStart = 0;
	}

	// The key that queries are counted under: the address for IPv4,
	// the /64 prefix for IPv6, where one client typically has many
	// addresses.
	#rateKey(address) {
		if (typeof(address) !== 'string') {
			return undefined;
		}
		try {
			let a = ipaddr.parse(address);
			if ((a.kind() === 'ipv6') && a.isIPv4MappedAddress()) {
				a = a.toIPv4Address();
			}
			if (a.kind() === 'ipv6') {
				return a.toNormalizedString().split(':').slice(0, 4).join(':');
			}
			return a.toString();
		} catch (e) {
			return address;
		}
	}

	// Returns true if the source of the query has used up its share
	// for the current second.
	#rateLimited(source) {
		if (this.#rateLimit < 1) {
			return false;
		}
		let now = Date.now();
		if (((now - this.#rateStart) >= RATE_PERIOD_MS) || (now < this.#rateStart)) {
			// A new period starts with the first query after the old one.
			this.#rateCounts.clear();
			this.#rateStart = now;
		}
		let key = this.#rateKey(source);
		if (key === undefined) {
			return false;
		}
		let n = (this.#rateCounts.get(key) ?? 0) + 1;
		if ((n === 1) && (this.#rateCounts.size >= 65536)) {
			// A flood from a huge number of sources. Start counting
			// from scratch instead of growing without a bound.
			this.#rateCounts.clear();
		}
		this.#rateCounts.set(key, n);
		return (n > this.#rateLimit);
	}

	// Answers one query. request is a parsed DNS packet and source the
	// address it came from, if known. Returns either { response }, a
	// packet to send back, or { dropped }, the reason why the query
	// gets no answer: notQuery, invalid, outOfZone, rateLimited or
	// error. With options.refuseOutOfZone a query for a name outside
	// the served domains gets a REFUSED response whatever the core was
	// configured with. Never throws.
	answer(request, source, options) {
		try {
			return this.#answer(request, source, options);
		} catch (e) {
			// Nothing a client sends may take the server down.
			this.#stat.dropped.error++;
			if (this.#debug) {
				log.debug('response: NONE <error>', e);
			}
			return { dropped: 'error' };
		}
	}

	// Counts a packet that a transport could not even parse.
	countInvalid() {
		this.#stat.dropped.invalid++;
	}

	#answer(request, source, options) {
		this.#stat.queries++;
		if (this.#rateLimited(source)) {
			this.#stat.dropped.rateLimited++;
			return { dropped: 'rateLimited' };
		}
		let header = request?.header;
		// Only plain queries with exactly one question are served.
		// Responses, other operations (UPDATE, NOTIFY and so on) and
		// packets with several questions are ignored.
		if (! (header && (header.qr === 0) && (header.opcode === 0) &&
			   Array.isArray(request.questions) && (request.questions.length === 1))) {
			this.#stat.dropped.notQuery++;
			if (this.#debug) {
				log.debug('response: NONE <not-a-query>');
			}
			return { dropped: 'notQuery' };
		}
		let q = request.questions[0];
		if (this.#debug) {
			log.debug('query:', JSON.stringify(q, null, 2));
		}
		if (! ((q?.class === dns2.Packet.CLASS.IN) && Number.isSafeInteger(q?.type) && (typeof(q?.name) === 'string'))) {
			this.#stat.dropped.invalid++;
			if (this.#debug) {
				log.debug('response: NONE <invalid-query>');
			}
			return { dropped: 'invalid' };
		}
		let r;
		if (typeof(this.#db.lookup) === 'function') {
			r = this.#db.lookup(q.name, q.type);
		} else {
			// A database that only has the older get() interface.
			let answers = this.#db.get(q.name, q.type);
			r = (answers === false) ? false : { rcode: dns2.Packet.RCODE.NOERROR, answers: answers ?? [] };
		}
		const response = dns2.Packet.createResponseFromRequest(request);
		// A client that uses EDNS gets an OPT record back.
		let edns = (request.additionals ?? []).some((x) => (x?.type === dns2.Packet.TYPE.EDNS));
		if (r === false) {
			// Query didn't match to any domain we are serving, so
			// we don't bother answering. It's probably a
			// configuration error, hostile probing, or DNS
			// applification attack anyways.
			if (! (options?.refuseOutOfZone ?? this.#refuse)) {
				this.#stat.dropped.outOfZone++;
				if (this.#debug) {
					log.debug('response: NONE <not-allowed> (' + q.name + ')');
				}
				return { dropped: 'outOfZone' };
			}
			this.#stat.refused++;
			r = { rcode: dns2.Packet.RCODE.REFUSED, aa: false, answers: [] };
		}
		response.header.rcode = r.rcode;
		response.header.aa = (r.aa ?? true) ? 1 : 0;
		response.answers.push(...r.answers);
		response.authorities.push(...(r.authorities ?? []));
		response.additionals.push(...(r.additionals ?? []));
		if (edns) {
			response.additionals.push(Object.assign({ name: '' }, dns2.Packet.Resource.EDNS([], { udpPayloadSize: EDNS_UDP_PAYLOAD_SIZE })));
		}
		if (r.rcode === dns2.Packet.RCODE.REFUSED) {
			/*NOTHING*/
		} else if (r.rcode === dns2.Packet.RCODE.NXDOMAIN) {
			this.#stat.nxdomain++;
		} else if (r.answers.length < 1) {
			// We don't have data that was asked for, but the
			// query was at least inside our domains.
			this.#stat.empty++;
		}
		if (this.#debug) {
			log.debug('response:', JSON.stringify(r.answers, null, 2));
		}
		this.#stat.answered++;
		return { response: response };
	}

	// Counters since the start: queries received, queries answered,
	// and the queries that were dropped by reason.
	stats() {
		let rv = Object.assign({}, this.#stat);
		rv.dropped = Object.assign({}, this.#stat.dropped);
		return rv;
	}

}

module.exports = DnsCore;
