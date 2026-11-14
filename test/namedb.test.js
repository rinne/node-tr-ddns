'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { lib, Packet, captureConsole } = require('./helpers');

const { NameDB } = lib;
const T = Packet.TYPE;

describe('NameDB', function() {

	let db;

	beforeEach(function() {
		db = new NameDB();
	});

	afterEach(function() {
		db.close();
	});

	describe('name validation', function() {

		test('accepts ordinary host names', function() {
			for (let n of [ 'a.b', 'host.example.com', 'HOST.Example.COM', 'a-b.c-d.e', '1.2.3.example', 'x'.repeat(63) + '.com' ]) {
				assert.equal(db.valid(n), true, n);
			}
		});

		test('accepts an underscore at the start of the first label', function() {
			assert.equal(db.valid('_acme-challenge.example.com'), true);
		});

		test('rejects malformed names', function() {
			for (let n of [ '', 'single', '.a.b', 'a..b', '-a.b', 'a-.b', 'a b.c', 'a.b/c', 'x'.repeat(64) + '.com', 'a.' + 'b'.repeat(64),
							undefined, null, 1, {}, [ 'a.b' ] ]) {
				assert.equal(db.valid(n), false, String(n));
			}
			assert.equal(db.valid(('a'.repeat(60) + '.').repeat(5) + 'com'), false);
		});

		test('validDomain accepts single labels and rejects non-strings', function() {
			assert.equal(db.validDomain('test'), true);
			assert.equal(db.validDomain('example.com'), true);
			assert.equal(db.validDomain(''), false);
			assert.equal(db.validDomain(undefined), false);
			assert.equal(db.validDomain('exa mple.com'), false);
		});

	});

	describe('domains', function() {

		test('adds a domain and emits adddomain with the lower case name', function() {
			let events = [];
			db.on('adddomain', (n) => events.push(n));
			db.addDomain('Example.COM');
			assert.deepEqual(events, [ 'example.com' ]);
			assert.equal(db.stats().domains, 1);
			assert.equal(db.dump().domains[0].name, 'Example.COM');
			assert.equal(db.dump().domains[0].lcname, 'example.com');
		});

		test('rejects duplicates, parents and subdomains of served domains', function() {
			db.addDomain('example.com');
			assert.throws(() => db.addDomain('example.com'));
			assert.throws(() => db.addDomain('EXAMPLE.com'));
			assert.throws(() => db.addDomain('sub.example.com'));
			assert.throws(() => db.addDomain('com'));
			assert.throws(() => db.addDomain('not valid'));
			db.addDomain('example.org');
			db.addDomain('notexample.com');
			assert.equal(db.stats().domains, 3);
		});

		test('removeDomain removes the hosts of the domain', function() {
			let events = [];
			db.on('removedomain', (n) => events.push(n));
			db.addDomain('example.com');
			db.addDomain('example.org');
			db.set('a.example.com', { a: '1.2.3.4' });
			db.set('a.example.org', { a: '1.2.3.4' });
			assert.equal(db.removeDomain('EXAMPLE.com'), true);
			assert.equal(db.removeDomain('example.com'), false);
			assert.equal(db.removeDomain(7), false);
			assert.deepEqual(events, [ 'example.com' ]);
			assert.deepEqual(db.dump().hosts.map((h) => h.lcname), [ 'a.example.org' ]);
		});

		test('flush removes hosts and domains', function() {
			let flushed = 0;
			db.on('flush', () => flushed++);
			db.addDomain('example.com');
			db.set('a.example.com', { a: '1.2.3.4' });
			db.flush();
			assert.equal(flushed, 1);
			assert.deepEqual(db.stats().domains, 0);
			assert.deepEqual(db.stats().hosts, 0);
		});

	});

	describe('set', function() {

		beforeEach(function() {
			db.addDomain('example.com');
		});

		test('stores single values and emits add, then update', function() {
			let events = [];
			db.on('add', (n) => events.push('add:' + n));
			db.on('update', (n) => events.push('update:' + n));
			assert.equal(db.set('Host.Example.com', { a: '1.2.3.4', aaaa: '2001:db8::1', txt: 'hello', mx: 'mail.example.com' }), true);
			assert.equal(db.set('host.example.com', { a: '5.6.7.8' }), true);
			assert.deepEqual(events, [ 'add:host.example.com', 'update:host.example.com' ]);
			let h = db.dump().hosts[0];
			assert.equal(h.name, 'host.example.com');
			assert.equal(h.domain, 'example.com');
			assert.deepEqual(h.data, { a: [ '5.6.7.8' ], aaaa: [], txt: [], mx: [] });
			assert.equal(h.expires, null);
		});

		test('normalises IPv6 addresses', function() {
			db.set('h.example.com', { aaaa: '2001:db8::1' });
			assert.deepEqual(db.dump().hosts[0].data.aaaa, [ '2001:db8:0:0:0:0:0:1' ]);
		});

		test('accepts arrays and sets of values', function() {
			assert.equal(db.set('h.example.com', { a: [ '1.1.1.1', '2.2.2.2' ], txt: new Set([ 'x', 'y' ]) }), true);
			let d = db.dump().hosts[0].data;
			assert.deepEqual(d.a, [ '1.1.1.1', '2.2.2.2' ]);
			assert.deepEqual(d.txt, [ 'x', 'y' ]);
		});

		test('refuses invalid input', function() {
			assert.equal(db.set('h.example.org', { a: '1.2.3.4' }), false, 'outside served domains');
			assert.equal(db.set('not valid', { a: '1.2.3.4' }), false);
			assert.equal(db.set('h.example.com', null), false);
			assert.equal(db.set('h.example.com', 'x'), false);
			assert.equal(db.set('h.example.com', { a: 'bogus' }), false);
			assert.equal(db.set('h.example.com', { a: 7 }), false);
			assert.equal(db.set('h.example.com', { aaaa: '1.2.3.4' }), false);
			assert.equal(db.set('h.example.com', { txt: 7 }), false);
			assert.equal(db.set('h.example.com', { mx: 'not valid' }), false);
			assert.equal(db.set('h.example.com', { a: '1.2.3.4' }, -1), false);
			assert.equal(db.set('h.example.com', { a: '1.2.3.4' }, 1.5), false);
			assert.equal(db.set('h.example.com', { a: '1.2.3.4' }, 'x'), false);
			assert.equal(db.stats().hosts, 0);
		});

		test('a host may sit at the apex of a domain', function() {
			assert.equal(db.set('example.com', { a: '1.2.3.4' }), true);
		});

		test('replaces all records without merge', function() {
			db.set('h.example.com', { a: '1.2.3.4', txt: 'hello' });
			db.set('h.example.com', { aaaa: '2001:db8::1' });
			assert.deepEqual(db.dump().hosts[0].data, { a: [], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [], mx: [] });
		});

		test('merge keeps record types that are not mentioned', function() {
			db.set('h.example.com', { a: '1.2.3.4', txt: 'hello' });
			db.set('h.example.com', { aaaa: '2001:db8::1' }, undefined, true);
			let d = db.dump().hosts[0].data;
			assert.deepEqual(d.a, [ '1.2.3.4' ]);
			assert.deepEqual(d.aaaa, [ '2001:db8:0:0:0:0:0:1' ]);
			assert.deepEqual(d.txt, [ 'hello' ]);
		});

		test('merge adds a single value to the existing ones', function() {
			db.set('h.example.com', { a: '1.2.3.4' });
			db.set('h.example.com', { a: '5.6.7.8' }, undefined, true);
			assert.deepEqual(db.dump().hosts[0].data.a.sort(), [ '1.2.3.4', '5.6.7.8' ]);
		});

		test('merge with an empty string removes that record type only', function() {
			db.set('h.example.com', { a: '1.2.3.4', txt: 'hello' });
			db.set('h.example.com', { txt: '' }, undefined, true);
			let d = db.dump().hosts[0].data;
			assert.deepEqual(d.a, [ '1.2.3.4' ]);
			assert.deepEqual(d.txt, []);
		});

		test('merge does not copy TXT values into MX', function() {
			db.set('h.example.com', { txt: 'hello', mx: 'mail.example.com' });
			db.set('h.example.com', { a: '1.2.3.4' }, undefined, true);
			assert.deepEqual(db.dump().hosts[0].data.mx, [ 'mail.example.com' ]);
		});

		test('merge does not keep the old expiry', function() {
			db.set('h.example.com', { a: '1.2.3.4' }, 60000);
			assert.equal(typeof(db.dump().hosts[0].expires), 'number');
			db.set('h.example.com', { txt: 'x' }, undefined, true);
			assert.equal(db.dump().hosts[0].expires, null);
		});

		test('remove deletes the host and emits remove', function() {
			let events = [];
			db.on('remove', (n) => events.push(n));
			db.set('h.example.com', { a: '1.2.3.4' });
			assert.equal(db.remove('H.example.com'), true);
			assert.equal(db.remove('h.example.com'), false);
			assert.equal(db.remove('not valid'), false);
			assert.deepEqual(events, [ 'h.example.com' ]);
		});

		test('getHostData returns copies', function() {
			db.set('h.example.com', { a: '1.2.3.4' });
			let d = db.getHostData('h.example.com');
			assert.deepEqual([ ...d.a ], [ '1.2.3.4' ]);
			d.a.add('9.9.9.9');
			assert.deepEqual(db.dump().hosts[0].data.a, [ '1.2.3.4' ]);
			assert.deepEqual([ ...db.getHostData('other.example.com').a ], []);
			assert.equal(db.getHostData('h.example.org'), undefined);
			assert.equal(db.getHostData('not valid'), false);
		});

	});

	describe('expiry', function() {

		test('a host with a lifetime disappears and emits remove', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				let events = [];
				d.on('remove', (n) => events.push(n));
				d.addDomain('example.com');
				d.set('h.example.com', { a: '1.2.3.4' }, 5000);
				assert.equal(d.dump().hosts[0].expires, Date.now() + 5000);
				t.mock.timers.tick(4999);
				assert.equal(d.stats().hosts, 1);
				t.mock.timers.tick(1);
				assert.equal(d.stats().hosts, 0);
				assert.deepEqual(events, [ 'h.example.com' ]);
				assert.deepEqual(d.get('h.example.com', T.A), []);
			} finally {
				d.close();
				// The database of the enclosing suite was created with the
				// real timers and must be closed with them.
				t.mock.timers.reset();
			}
		});

		test('setting the host again replaces the lifetime', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				d.addDomain('example.com');
				d.set('h.example.com', { a: '1.2.3.4' }, 5000);
				d.set('h.example.com', { a: '1.2.3.4' }, 20000);
				t.mock.timers.tick(10000);
				assert.equal(d.stats().hosts, 1);
				d.set('h.example.com', { a: '1.2.3.4' });
				t.mock.timers.tick(100000);
				assert.equal(d.stats().hosts, 1);
			} finally {
				d.close();
				// The database of the enclosing suite was created with the
				// real timers and must be closed with them.
				t.mock.timers.reset();
			}
		});

	});

	describe('lookups', function() {

		beforeEach(function() {
			db.addDomain('example.com');
			db.set('h.example.com', { a: [ '1.2.3.4', '5.6.7.8' ], aaaa: '2001:db8::1', txt: 'hello', mx: 'mail.example.com' });
		});

		test('returns false outside the served domains and for invalid names', function() {
			assert.equal(db.get('h.example.org', T.A), false);
			assert.equal(db.get('not valid', T.A), false);
			let s = db.stats();
			assert.equal(s.lookup.total, 2);
			assert.equal(s.lookup.errors, 2);
		});

		test('returns records with name, type, class and ttl', function() {
			assert.deepEqual(db.get('H.Example.com', T.A),
							 [ { name: 'h.example.com', type: T.A, 'class': 1, ttl: 60, address: '1.2.3.4' },
							   { name: 'h.example.com', type: T.A, 'class': 1, ttl: 60, address: '5.6.7.8' } ]);
			assert.deepEqual(db.get('h.example.com', T.AAAA).map((r) => r.address), [ '2001:db8:0:0:0:0:0:1' ]);
			assert.deepEqual(db.get('h.example.com', T.TXT).map((r) => r.data), [ 'hello' ]);
		});

		test('returns an empty answer for names in a served domain without data', function() {
			assert.deepEqual(db.get('other.example.com', T.A), []);
			assert.deepEqual(db.get('h.example.com', T.CNAME), []);
			assert.deepEqual(db.get('h.example.com', T.SRV), []);
		});

		test('answers SOA and NS at the apex only', function() {
			let soa = db.get('example.com', T.SOA);
			assert.equal(soa.length, 1);
			assert.equal(soa[0].primary, 'example.com');
			assert.equal(soa[0].admin, 'postmaster.example.com');
			assert.equal(soa[0].refresh, 300);
			assert.equal(soa[0].retry, 3);
			assert.equal(soa[0].expiration, 10);
			assert.equal(soa[0].minimum, 10);
			assert.ok(Number.isSafeInteger(soa[0].serial) && (soa[0].serial > 0));
			assert.deepEqual(db.get('example.com', T.NS).map((r) => r.ns), [ 'example.com' ]);
			assert.deepEqual(db.get('h.example.com', T.SOA), []);
			assert.deepEqual(db.get('h.example.com', T.NS), []);
		});

		test('the serial grows with every change', function() {
			let s0 = db.get('example.com', T.SOA)[0].serial;
			db.set('x.example.com', { a: '1.1.1.1' });
			let s1 = db.get('example.com', T.SOA)[0].serial;
			db.remove('x.example.com');
			let s2 = db.get('example.com', T.SOA)[0].serial;
			assert.equal(s1, s0 + 1);
			assert.equal(s2, s1 + 1);
		});

		test('lookup tells apart outside, nonexistent and unanswerable', function() {
			assert.equal(db.lookup('h.example.org', T.A), false);
			assert.equal(db.lookup(7, T.A), false);
			assert.deepEqual(db.lookup('bad_name.example.com', T.A), { rcode: 3, answers: [] });
			assert.deepEqual(db.lookup('h.example.com', 65), { rcode: 0, answers: [] });
			assert.equal(db.lookup('h.example.com', T.A).answers.length, 2);
		});

		test('a long TXT value is split into strings of at most 255 bytes', function() {
			db.set('long.example.com', { txt: 'ä'.repeat(200) });
			let data = db.get('long.example.com', T.TXT)[0].data;
			assert.ok(Array.isArray(data));
			assert.deepEqual(data.map((b) => b.length), [ 255, 145 ]);
			assert.equal(Buffer.concat(data).toString('utf8'), 'ä'.repeat(200));
			assert.equal(db.get('h.example.com', T.TXT)[0].data, 'hello');
		});

		test('getHostExpires', function() {
			assert.equal(db.getHostExpires('h.example.com'), null);
			assert.equal(db.getHostExpires('nope.example.com'), undefined);
			db.set('t.example.com', { a: '1.2.3.4' }, 60000);
			assert.ok(db.getHostExpires('t.example.com') > Date.now());
		});

		test('answers MX', function() {
			let mx = db.get('h.example.com', T.MX);
			assert.deepEqual(mx.map((r) => [ r.exchange, r.priority ]), [ [ 'mail.example.com', 1 ] ]);
		});

	});

	describe('dump', function() {

		test('has the persisted shape', function() {
			db.addDomain('example.com');
			db.set('h.example.com', { a: '1.2.3.4' }, 60000);
			let d = db.dump();
			assert.deepEqual(Object.keys(d).sort(), [ 'domains', 'hosts' ]);
			assert.deepEqual(Object.keys(d.hosts[0]).sort(), [ 'data', 'domain', 'expires', 'lcname', 'name' ]);
			assert.deepEqual(Object.keys(d.domains[0]).sort(), [ 'expires', 'lcname', 'name', 'serial' ]);
			assert.doesNotThrow(() => JSON.stringify(d));
		});

		test('can be loaded into another database', function() {
			db.addDomain('example.com');
			db.set('h.example.com', { a: [ '1.2.3.4', '5.6.7.8' ], txt: 'hello' });
			let d = JSON.parse(JSON.stringify(db.dump()));
			let other = new NameDB();
			try {
				for (let dom of d.domains) {
					other.addDomain(dom.name);
				}
				for (let h of d.hosts) {
					assert.equal(other.set(h.name, h.data), true);
				}
				assert.deepEqual(other.dump().hosts, db.dump().hosts);
			} finally {
				other.close();
			}
		});

		test('does not print anything', async function() {
			db.addDomain('example.com');
			db.set('h.example.com', { a: '1.2.3.4' });
			let lines = await captureConsole(() => { db.dump(); });
			assert.deepEqual(lines, []);
		});

	});

});
