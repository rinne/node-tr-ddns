'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');

const { lib, TYPE, RCODE, dohQuery, dnsQuery, buildQuery, socketCall, apiCall, tmpDir, freePort, freeTcpPort,
		startCli, runCli, waitFor, captureConsole } = require('./helpers');

const { NameDB, DnsCore, DohServer, NameServer, ApiCore } = lib;

// A database with what the tests ask for.
function database() {
	let db = new NameDB();
	db.addDomain('example.com');
	db.set('h.example.com', { a: [ '1.2.3.4', '5.6.7.8' ], txt: 'x'.repeat(300) });
	db.set('alias.example.com', { cname: 'h.example.com' });
	let many = [];
	for (let i = 0; i < 80; i++) {
		many.push('10.0.0.' + i);
	}
	db.set('many.example.com', { a: many });
	return db;
}

async function startDoh(options) {
	let db = database();
	let port = await freeTcpPort();
	let doh = new DohServer(Object.assign({ nameDB: db, port: port }, options));
	await once(doh, 'ready');
	return { db, doh, port, where: (options?.socket ? { socket: options.socket } : { port }),
			 close: async function() { await doh.close(); db.close(); } };
}

describe('DoH server', function() {

	let s;

	before(async function() {
		s = await startDoh();
	});

	after(async function() {
		await s.close();
	});

	for (let method of [ 'GET', 'POST' ]) {

		describe('with ' + method, function() {

			test('answers a query with a DNS message', async function() {
				let r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method, id: 0 });
				assert.equal(r.status, 200);
				assert.equal(r.headers['content-type'], 'application/dns-message');
				assert.equal(Number.parseInt(r.headers['content-length']), r.raw.length);
				assert.deepEqual([ r.packet.header.id, r.packet.header.qr, r.packet.header.aa, r.packet.header.rcode ], [ 0, 1, 1, RCODE.NOERROR ]);
				assert.deepEqual(r.packet.answers.map((a) => a.address).sort(), [ '1.2.3.4', '5.6.7.8' ]);
			});

			test('gives the answers of the DNS port: no data, no such name, aliases', async function() {
				let r = await dohQuery(s.where, 'h.example.com', TYPE.MX, { method });
				assert.deepEqual([ r.status, r.packet.header.rcode, r.packet.answers.length, r.packet.authorities[0].type ], [ 200, RCODE.NOERROR, 0, TYPE.SOA ]);
				r = await dohQuery(s.where, 'nothing.example.com', TYPE.A, { method });
				assert.deepEqual([ r.status, r.packet.header.rcode, r.packet.authorities[0].type ], [ 200, RCODE.NXDOMAIN, TYPE.SOA ]);
				r = await dohQuery(s.where, 'alias.example.com', TYPE.A, { method });
				assert.deepEqual(r.packet.answers.map((a) => a.type), [ TYPE.CNAME, TYPE.A, TYPE.A ]);
				r = await dohQuery(s.where, 'h.example.com', TYPE.TXT, { method });
				assert.deepEqual(r.packet.answers[0].data, [ 'x'.repeat(255), 'x'.repeat(45) ]);
			});

			test('refuses a name outside the served domains, where the DNS port stays silent', async function() {
				let r = await dohQuery(s.where, 'h.example.org', TYPE.A, { method });
				assert.equal(r.status, 200);
				assert.equal(r.packet.header.rcode, RCODE.REFUSED);
				assert.equal(r.packet.header.aa, 0);
				assert.equal(r.packet.answers.length + r.packet.authorities.length, 0);
				assert.equal(r.headers['cache-control'], 'no-store');
			});

			test('answers 400 to what is not a query that can be answered', async function() {
				for (let [ what, opts ] of [ [ 'a response', { qr: 1 } ], [ 'an update', { opcode: 5 } ],
											 [ 'two questions', { extraQuestions: [ { name: 'h.example.com', type: TYPE.AAAA } ] } ],
											 [ 'class CH', { 'class': 3 } ] ]) {
					let r = await dohQuery(s.where, 'h.example.com', TYPE.A, Object.assign({ method }, opts));
					assert.equal(r.status, 400, what);
					assert.match(r.headers['content-type'], /^text\/plain/);
				}
				for (let message of [ Buffer.alloc(5), Buffer.alloc(11, 1), Buffer.concat([ buildQuery('h.example.com', TYPE.A).subarray(0, 14), Buffer.alloc(3, 0xff) ]) ]) {
					let r = await dohQuery(s.where, undefined, undefined, { method, message });
					assert.equal(r.status, 400, message.toString('hex'));
				}
			});

			test('does not truncate a large answer', async function() {
				let r = await dohQuery(s.where, 'many.example.com', TYPE.A, { method });
				assert.equal(r.packet.header.tc, 0);
				assert.equal(r.packet.answers.length, 80);
				assert.ok(r.raw.length > 512);
			});

			test('returns an OPT record to a client that sent one', async function() {
				let r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method, edns: true });
				assert.equal(r.packet.additionals.filter((a) => (a.type === TYPE.EDNS)).length, 1);
				r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method });
				assert.equal(r.packet.additionals.length, 0);
			});

		});

	}

	test('says how long an answer may be cached', async function() {
		assert.equal((await dohQuery(s.where, 'h.example.com', TYPE.A)).headers['cache-control'], 'max-age=60');
		assert.equal((await dohQuery(s.where, 'nothing.example.com', TYPE.A)).headers['cache-control'], 'max-age=10', 'the ttl of the SOA record');
		assert.equal((await dohQuery(s.where, 'h.example.com', TYPE.MX)).headers['cache-control'], 'max-age=10');
		s.db.addDomain('slow.test', { ttl: 3600, minimum: 900 });
		s.db.set('h.slow.test', { a: '1.2.3.4' });
		assert.equal((await dohQuery(s.where, 'h.slow.test', TYPE.A)).headers['cache-control'], 'max-age=3600');
		assert.equal((await dohQuery(s.where, 'x.slow.test', TYPE.A)).headers['cache-control'], 'max-age=900');
	});

	test('GET needs the query in the dns parameter as base64url', async function() {
		let q = buildQuery('h.example.com', TYPE.A).toString('base64url');
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?dns=' + q })).status, 200);
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?other=1&dns=' + q + '&x=y' })).status, 200);
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?dns=' + q + '==' })).status, 200, 'padding is tolerated');
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query' })).status, 400);
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?dns=' })).status, 400);
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?dns=' + q.slice(0, 8) + '*' + q.slice(8) })).status, 400);
		assert.equal((await dohQuery(s.where, undefined, undefined, { path: '/dns-query?dns=' + 'A'.repeat(8000) })).status, 400, 'bytes that are not a query');
	});

	test('POST needs the DNS message content type and a message of a possible size', async function() {
		assert.equal((await dohQuery(s.where, 'h.example.com', TYPE.A, { method: 'POST', headers: { 'Content-Type': 'Application/DNS-Message; charset=x' } })).status, 200);
		let r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
		assert.equal(r.status, 415);
		r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method: 'POST', headers: { 'Content-Type': '' } });
		assert.equal(r.status, 415);
		r = await dohQuery(s.where, undefined, undefined, { method: 'POST', message: Buffer.alloc(70000) });
		assert.equal(r.status, 413);
	});

	test('serves /dns-query and nothing else', async function() {
		for (let p of [ '/', '/dump', '/flush', '/host?host=h.example.com&a=9.9.9.9', '/stats', '/dns-query/', '/dns-query/x', '/DNS-QUERY', '//dns-query' ]) {
			let r = await dohQuery(s.where, undefined, undefined, { path: p });
			assert.equal(r.status, 404, p);
		}
		assert.deepEqual(s.db.dump().hosts.find((h) => (h.lcname === 'h.example.com')).data.a, [ '1.2.3.4', '5.6.7.8' ]);
	});

	test('allows GET and POST only', async function() {
		for (let method of [ 'PUT', 'DELETE', 'HEAD', 'PATCH' ]) {
			let r = await dohQuery(s.where, 'h.example.com', TYPE.A, { method, headers: { 'Content-Type': 'application/dns-message' } });
			assert.equal(r.status, 405, method);
			assert.equal(r.headers.allow, 'GET, POST');
		}
	});

	test('counts requests by how they ended', async function() {
		let a = s.doh.stats();
		await dohQuery(s.where, 'h.example.com', TYPE.A);
		await dohQuery(s.where, 'h.example.org', TYPE.A);
		await dohQuery(s.where, 'h.example.com', TYPE.A, { qr: 1 });
		await dohQuery(s.where, undefined, undefined, { path: '/nope' });
		let b = s.doh.stats();
		assert.deepEqual([ b.requests - a.requests, b.answered - a.answered, b.badRequest - a.badRequest, b.notFound - a.notFound, b.rateLimited, b.errors ],
						 [ 4, 2, 1, 1, 0, 0 ]);
		let api = new ApiCore({ nameDB: s.db, dohServer: s.doh });
		assert.deepEqual(api.handle({ path: '/stats' }).body.data.doh, b);
	});

	test('a failure while answering is a 500 and is logged', async function() {
		let db = new NameDB();
		let port = await freeTcpPort();
		let doh = new DohServer({ core: new DnsCore({ nameDB: { get: () => [], lookup: () => ({ rcode: 0, answers: [ { name: 'x.example.com', type: 1, 'class': 1, ttl: 1, address: 'not an address' } ] }) } }), port });
		await once(doh, 'ready');
		try {
			let r;
			let lines = await captureConsole(async function() { r = await dohQuery({ port }, 'x.example.com', TYPE.A); });
			assert.equal(r.status, 500);
			assert.equal(r.text, 'Internal Server Error\n');
			assert.ok(lines.some((l) => /DohServer/.test(l)));
			assert.equal(doh.stats().errors, 1);
		} finally {
			await doh.close();
			db.close();
		}
	});

});

describe('DoH rate limiting and the address of the client', function() {

	// Asks n times and tells which were answered.
	async function burst(where, n, headers) {
		let rv = [];
		for (let i = 0; i < n; i++) {
			rv.push((await dohQuery(where, 'h.example.com', TYPE.A, { headers })).status);
		}
		return rv;
	}

	// Starts a counting period of the rate limit with one answered query.
	async function freshPeriod(where, headers) {
		for (let i = 0; i < 200; i++) {
			if ((await dohQuery(where, 'h.example.com', TYPE.A, { headers })).status === 429) {
				break;
			}
		}
		for (let i = 0; i < 200; i++) {
			if ((await dohQuery(where, 'h.example.com', TYPE.A, { headers })).status === 200) {
				return;
			}
			await new Promise((r) => setTimeout(r, 15));
		}
		throw new Error('The rate limit never opened again');
	}

	test('a source over the limit gets 429', async function() {
		let s = await startDoh({ rateLimit: 4 });
		try {
			await freshPeriod(s.where);
			assert.deepEqual(await burst(s.where, 6), [ 200, 200, 200, 429, 429, 429 ]);
			let r = await dohQuery(s.where, 'h.example.com', TYPE.A);
			assert.equal(r.status, 429);
			assert.equal(r.headers['retry-after'], '1');
			assert.ok(s.doh.stats().rateLimited >= 4);
		} finally {
			await s.close();
		}
	});

	test('without trusted proxies X-Forwarded-For is ignored', async function() {
		let s = await startDoh({ rateLimit: 3 });
		try {
			await freshPeriod(s.where);
			let statuses = [];
			for (let i = 0; i < 4; i++) {
				statuses.push((await dohQuery(s.where, 'h.example.com', TYPE.A, { headers: { 'X-Forwarded-For': '203.0.113.' + i } })).status);
			}
			assert.deepEqual(statuses, [ 200, 200, 429, 429 ], 'a forged header does not buy a limit of its own');
		} finally {
			await s.close();
		}
	});

	test('with one trusted proxy the client is the last address in X-Forwarded-For', async function() {
		let s = await startDoh({ rateLimit: 2, trustedProxyHops: 1 });
		try {
			await freshPeriod(s.where, { 'X-Forwarded-For': '198.51.100.1' });
			assert.deepEqual(await burst(s.where, 3, { 'X-Forwarded-For': '198.51.100.1' }), [ 200, 429, 429 ]);
			assert.deepEqual(await burst(s.where, 3, { 'X-Forwarded-For': '198.51.100.2' }), [ 200, 200, 429 ], 'another client has its own limit');
			assert.deepEqual(await burst(s.where, 2, { 'X-Forwarded-For': '198.51.100.3, 198.51.100.1' }), [ 429, 429 ], 'what is further left does not count');
			assert.deepEqual(await burst(s.where, 3, { 'X-Forwarded-For': '10.9.9.9,  198.51.100.4 ' }), [ 200, 200, 429 ]);
		} finally {
			await s.close();
		}
	});

	test('with two trusted proxies it is the second address from the right', async function() {
		let s = await startDoh({ rateLimit: 2, trustedProxyHops: 2 });
		try {
			let h = (client) => ({ 'X-Forwarded-For': 'forged, ' + client + ', 10.0.0.1' });
			await freshPeriod(s.where, h('198.51.100.1'));
			assert.deepEqual(await burst(s.where, 2, h('198.51.100.1')), [ 200, 429 ]);
			assert.deepEqual(await burst(s.where, 3, h('198.51.100.2')), [ 200, 200, 429 ]);
			assert.deepEqual(await burst(s.where, 3, { 'X-Forwarded-For': '198.51.100.3, 10.0.0.1, 10.0.0.2' }), [ 200, 200, 429 ], 'the address is taken by its place, not by what the others are');
		} finally {
			await s.close();
		}
	});

	test('a header that is missing, too short or not an address leaves the peer as the client', async function() {
		let s = await startDoh({ rateLimit: 3, trustedProxyHops: 2 });
		try {
			await freshPeriod(s.where);
			let statuses = [];
			statuses.push((await dohQuery(s.where, 'h.example.com', TYPE.A)).status);
			statuses.push((await dohQuery(s.where, 'h.example.com', TYPE.A, { headers: { 'X-Forwarded-For': '198.51.100.1' } })).status);
			statuses.push((await dohQuery(s.where, 'h.example.com', TYPE.A, { headers: { 'X-Forwarded-For': 'unknown, 10.0.0.1' } })).status);
			statuses.push((await dohQuery(s.where, 'h.example.com', TYPE.A, { headers: { 'X-Forwarded-For': ' , ' } })).status);
			assert.deepEqual(statuses, [ 200, 200, 429, 429 ], 'all four were counted for the peer');
		} finally {
			await s.close();
		}
	});

	test('an address may come with a port or in brackets', async function() {
		let s = await startDoh({ rateLimit: 2, trustedProxyHops: 1 });
		try {
			await freshPeriod(s.where, { 'X-Forwarded-For': '198.51.100.1' });
			assert.deepEqual(await burst(s.where, 2, { 'X-Forwarded-For': '198.51.100.1:4711' }), [ 200, 429 ], 'the same client as without the port');
			await burst(s.where, 2, { 'X-Forwarded-For': '2001:db8:1:2::1' });
			assert.deepEqual(await burst(s.where, 2, { 'X-Forwarded-For': '[2001:db8:1:2::99]:4711' }), [ 429, 429 ], 'the same /64 as the plain address');
		} finally {
			await s.close();
		}
	});

	test('the limit and the counters are shared with the DNS port when the core is', async function() {
		let db = database();
		let core = new DnsCore({ nameDB: db, rateLimit: 3 });
		let port = await freePort();
		let dns = new NameServer({ core, udp: true, udpListenPort: port, udpListenAddress: '127.0.0.1' });
		let doh = new DohServer({ core, port });
		await Promise.all([ once(dns, 'ready'), once(doh, 'ready') ]);
		try {
			await freshPeriod({ port });
			let results = [ (await dnsQuery(port, 'h.example.com', TYPE.A, { timeoutMs: 40 })) !== null,
							(await dohQuery({ port }, 'h.example.com', TYPE.A)).status,
							(await dnsQuery(port, 'h.example.com', TYPE.A, { timeoutMs: 40 })) !== null,
							(await dohQuery({ port }, 'h.example.com', TYPE.A)).status ];
			assert.deepEqual(results, [ true, 200, false, 429 ]);
			assert.ok(dns.stats().queries >= 5, 'queries over HTTP are in the counters of the core');
		} finally {
			await doh.close();
			await dns.close();
			db.close();
		}
	});

});

describe('DohServer', function() {

	test('validates its options', function() {
		let db = new NameDB();
		try {
			assert.throws(() => new DohServer({}), /NameDB/);
			assert.throws(() => new DohServer({ core: {} }), /DnsCore/);
			assert.throws(() => new DohServer({ nameDB: db, address: 'bogus' }), /listen address/);
			assert.throws(() => new DohServer({ nameDB: db, port: 0 }), /listen port/);
			assert.throws(() => new DohServer({ nameDB: db, socket: '' }), /socket path/);
			assert.throws(() => new DohServer({ nameDB: db, socket: '/tmp/x', socketMode: 'rw' }), /mode/);
			for (let hops of [ -1, 1.5, 33, '1' ]) {
				assert.throws(() => new DohServer({ nameDB: db, trustedProxyHops: hops }), /proxy hops/);
			}
			assert.throws(() => new DohServer({ nameDB: db, rateLimit: -1 }), /rate limit/);
		} finally {
			db.close();
		}
	});

	test('listens on the loopback address by default', async function() {
		let s = await startDoh();
		try {
			assert.equal((await dohQuery({ port: s.port, address: '127.0.0.1' }, 'h.example.com', TYPE.A)).status, 200);
		} finally {
			await s.close();
		}
	});

	test('reports a port that is in use as an error event', async function() {
		let db = new NameDB();
		let blocker = require('node:net').createServer();
		await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
		let doh = new DohServer({ nameDB: db, port: blocker.address().port });
		try {
			let [ e ] = await once(doh, 'error');
			assert.equal(e.code, 'EADDRINUSE');
		} finally {
			await doh.close();
			blocker.close();
			db.close();
		}
	});

	test('can listen on a Unix domain socket, which is removed at close', async function() {
		let dir = tmpDir();
		let sock = path.join(dir, 'doh.sock');
		let s = await startDoh({ socket: sock, rateLimit: 2 });
		try {
			assert.ok(fs.statSync(sock).isSocket());
			assert.equal(fs.statSync(sock).mode & 0o777, 0o666, 'any local proxy may connect by default');
			let r = await dohQuery({ socket: sock }, 'h.example.com', TYPE.A, { method: 'POST' });
			assert.deepEqual([ r.status, r.packet.answers.length ], [ 200, 2 ]);
			let statuses = [];
			for (let i = 0; i < 6; i++) {
				statuses.push((await dohQuery({ socket: sock }, 'h.example.com', TYPE.A)).status);
			}
			assert.ok(statuses.includes(429), 'requests through the socket are one source');
		} finally {
			await s.close();
			assert.equal(fs.existsSync(sock), false);
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('the permissions of the socket can be chosen', async function() {
		let dir = tmpDir();
		let sock = path.join(dir, 'doh.sock');
		let s = await startDoh({ socket: sock, socketMode: '660' });
		try {
			assert.equal(fs.statSync(sock).mode & 0o777, 0o660);
		} finally {
			await s.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

});

describe('--doh', function() {

	async function start(t, extra, env) {
		let dir = tmpDir();
		let sock = path.join(dir, 'control.sock');
		let port = await freeTcpPort();
		let h = await startCli([ '--memory-only', '--control-socket=' + sock ].concat(extra(port, dir)), { env: env });
		t.after(async function() {
			await h.stop('SIGKILL');
			fs.rmSync(dir, { recursive: true, force: true });
		});
		await waitFor(() => (h.exited || fs.existsSync(sock)));
		assert.equal(h.exited, false, h.stderr);
		assert.equal((await socketCall(sock, '/domain', { domain: 'example.com' })).status, 200);
		assert.equal((await socketCall(sock, '/host', { host: 'h.example.com', a: '1.2.3.4' })).status, 200);
		return { h, dir, sock, port };
	}

	test('serves DNS over HTTP without the DNS ports', async function(t) {
		let s = await start(t, (port) => [ '--doh', '--doh-listen-port=' + port ]);
		await waitFor(async () => { try { return (await dohQuery({ port: s.port }, 'h.example.com', TYPE.A)).status === 200; } catch (e) { return false; } });
		let r = await dohQuery({ port: s.port }, 'h.example.com', TYPE.A, { method: 'POST' });
		assert.deepEqual(r.packet.answers.map((a) => a.address), [ '1.2.3.4' ]);
		assert.equal((await dohQuery({ port: s.port }, undefined, undefined, { path: '/dump' })).status, 404, 'the API is not there');
		let stats = (await socketCall(s.sock, '/stats')).body.data;
		assert.ok(stats.doh.answered >= 2);
		assert.ok(stats.dns.answered >= 2);
		assert.equal((await socketCall(s.sock, '/dns-query')).status, 404, 'and DoH is not on the control socket');
	});

	test('is off unless asked for', async function(t) {
		let s = await start(t, (port) => [ '--doh-listen-port=' + port ]);
		await assert.rejects(dohQuery({ port: s.port }, 'h.example.com', TYPE.A));
		assert.equal((await socketCall(s.sock, '/stats')).body.data.doh, undefined);
	});

	test('shares the rate limit and --dns-refuse-out-of-zone does not matter to it', async function(t) {
		let dnsPort = await freePort();
		let s = await start(t, (port) => [ '--doh', '--doh-listen-port=' + port, '--udp', '--udp-listen-address=127.0.0.1', '--udp-listen-port=' + dnsPort, '--dns-rate-limit=1000' ]);
		await waitFor(async () => { try { return (await dohQuery({ port: s.port }, 'h.example.com', TYPE.A)).status === 200; } catch (e) { return false; } });
		assert.equal((await dohQuery({ port: s.port }, 'x.example.org', TYPE.A)).packet.header.rcode, RCODE.REFUSED);
		assert.equal(await dnsQuery(dnsPort, 'x.example.org', TYPE.A, { timeoutMs: 150 }), null, 'the DNS port still stays silent');
	});

	test('can listen on a socket, with the options from the environment', async function(t) {
		let s = await start(t, () => [], { TR_DDNS_OPT_DOH: 'true', TR_DDNS_OPT_DOH_SOCKET: path.join(require('node:os').tmpdir(), 'tr-ddns-doh-' + process.pid + '.sock'),
										   TR_DDNS_OPT_DOH_SOCKET_MODE: '660', TR_DDNS_OPT_DOH_TRUSTED_PROXY_HOPS: '1', TR_DDNS_OPT_DNS_RATE_LIMIT: '2' });
		let sock = path.join(require('node:os').tmpdir(), 'tr-ddns-doh-' + process.pid + '.sock');
		await waitFor(() => fs.existsSync(sock));
		assert.equal(fs.statSync(sock).mode & 0o777, 0o660);
		let statuses = [];
		for (let i = 0; i < 6; i++) {
			statuses.push((await dohQuery({ socket: sock }, 'h.example.com', TYPE.A, { headers: { 'X-Forwarded-For': '198.51.100.' + i } })).status);
		}
		assert.deepEqual(statuses, [ 200, 200, 200, 200, 200, 200 ], 'each forwarded client has its own limit');
		await s.h.stop('SIGTERM');
		assert.equal(s.h.code, 0);
		assert.equal(fs.existsSync(sock), false);
	});

	test('a DoH listener that cannot be started ends the program', async function() {
		let blocker = require('node:net').createServer();
		await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
		try {
			let r = await runCli([ '--memory-only', '--doh', '--doh-listen-port=' + blocker.address().port ]);
			assert.equal(r.code, 1);
			assert.match(r.stderr, /Unable to start DoH server \(EADDRINUSE\)/);
			for (let bad of [ '--doh-listen-port=0', '--doh-listen-address=nope', '--doh-trusted-proxy-hops=33', '--doh-trusted-proxy-hops=x', '--doh-socket-mode=rw' ]) {
				r = await runCli([ '--memory-only', '--doh', bad ]);
				assert.notEqual(r.code, 0, bad);
			}
		} finally {
			blocker.close();
		}
	});

	test('the API port does not serve DoH', async function(t) {
		let apiPort = await freeTcpPort();
		let s = await start(t, (port) => [ '--doh', '--doh-listen-port=' + port, '--http-api', '--http-api-listen-address=127.0.0.1', '--http-api-listen-port=' + apiPort ]);
		await waitFor(async () => { try { return (await apiCall('http://127.0.0.1:' + apiPort, '/')).status === 200; } catch (e) { return false; } });
		assert.equal((await apiCall('http://127.0.0.1:' + apiPort, '/dns-query')).status, 404);
		void s;
	});

});
