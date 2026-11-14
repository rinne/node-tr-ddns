'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { lib, Packet, captureConsole, full } = require('./helpers');

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

		test('accepts an underscore at the start of any label', function() {
			for (let n of [ 'selector._domainkey.example.com', '_sip._tcp.example.com', '_a._b._c.example.com', 'x._y.com' ]) {
				assert.equal(db.valid(n), true, n);
			}
			for (let n of [ 'a_b.example.com', 'a_.example.com', '__a.example.com', '_.example.com', '_-a.example.com' ]) {
				assert.equal(db.valid(n), false, n);
			}
		});

		test('accepts a dot at the end', function() {
			assert.equal(db.valid('host.example.com.'), true);
			assert.equal(db.valid('host.example.com..'), false);
			assert.equal(db.valid('.'), false);
			assert.equal(db.validDomain('example.com.'), true);
		});

		test('limits the length of a label and of the whole name', function() {
			assert.equal(db.valid('_' + 'x'.repeat(62) + '.com'), true);
			assert.equal(db.valid('_' + 'x'.repeat(63) + '.com'), false);
			let long = ('a'.repeat(49) + '.').repeat(5) + 'com';
			assert.equal(long.length, 253);
			assert.equal(db.valid(long), true);
			assert.equal(db.valid(long + '.'), true);
			assert.equal(db.valid('b' + long), false);
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

		test('a dot at the end of a name makes no difference', function() {
			db.addDomain('Example.COM.');
			assert.equal(db.dump().domains[0].name, 'Example.COM');
			assert.throws(() => db.addDomain('example.com'));
			assert.equal(db.set('Host.example.com.', { a: '1.2.3.4' }), true);
			assert.equal(db.dump().hosts[0].name, 'Host.example.com');
			assert.equal(db.get('host.example.com.', T.A).length, 1);
			assert.equal(db.lookup('HOST.example.com.', T.A).answers.length, 1);
			assert.equal(db.getHostExpires('host.example.com.'), null);
			assert.deepEqual([ ...db.getHostData('host.example.com.').a ], [ '1.2.3.4' ]);
			assert.equal(db.remove('host.example.com.'), true);
			assert.equal(db.removeDomain('example.com.'), true);
		});

		describe('settings', function() {

			test('default to the domain as its own name server', function() {
				db.addDomain('Example.com');
				assert.deepEqual(db.getDomain('example.com'),
								 { name: 'Example.com', lcname: 'example.com', serial: db.get('example.com', T.SOA)[0].serial,
								   ns: [ 'example.com' ], admin: 'postmaster.example.com', ttl: 60, refresh: 300, retry: 3, expiration: 10, minimum: 10 });
				assert.equal(db.getDomain('example.org'), undefined);
				assert.equal(db.getDomain(7), undefined);
				assert.deepEqual(Object.keys(db.dump().domains[0]).sort(), [ 'expires', 'lcname', 'name', 'serial' ]);
			});

			test('can be given when the domain is added', function() {
				db.addDomain('example.com', { ns: [ 'NS1.example.net.', 'ns2.example.net', 'ns1.example.net' ], admin: 'hostmaster@example.com',
											  ttl: 300, refresh: 3600, retry: 600, expiration: 604800, minimum: 120 });
				let soa = db.get('example.com', T.SOA)[0];
				assert.equal(soa.primary, 'ns1.example.net');
				assert.equal(soa.admin, 'hostmaster.example.com');
				assert.deepEqual([ soa.ttl, soa.refresh, soa.retry, soa.expiration, soa.minimum ], [ 300, 3600, 600, 604800, 120 ]);
				assert.deepEqual(db.get('example.com', T.NS).map((r) => [ r.ns, r.ttl ]), [ [ 'ns1.example.net', 300 ], [ 'ns2.example.net', 300 ] ]);
				db.set('h.example.com', { a: '1.2.3.4' });
				assert.equal(db.get('h.example.com', T.A)[0].ttl, 300);
				let d = db.dump().domains[0];
				assert.deepEqual(d.ns, [ 'ns1.example.net', 'ns2.example.net' ]);
				assert.equal(d.admin, 'hostmaster.example.com');
				assert.equal(d.ttl, 300);
				assert.equal(d.expiration, 604800);
			});

			test('can be changed, and reset to the defaults', function() {
				let events = [];
				db.on('updatedomain', (n) => events.push(n));
				db.addDomain('example.com');
				let serial = db.getDomain('example.com').serial;
				assert.equal(db.setDomainOptions('Example.com.', { ns: 'ns.example.net', ttl: 120 }), true);
				assert.deepEqual(events, [ 'example.com' ]);
				assert.equal(db.getDomain('example.com').serial, serial + 1);
				assert.deepEqual(db.getDomain('example.com').ns, [ 'ns.example.net' ]);
				assert.equal(db.setDomainOptions('example.com', { minimum: 30 }), true);
				let d = db.getDomain('example.com');
				assert.deepEqual([ d.ns[0], d.ttl, d.minimum ], [ 'ns.example.net', 120, 30 ]);
				assert.equal(db.setDomainOptions('example.com', { ns: null, ttl: '', admin: 'ops.example.net' }), true);
				d = db.getDomain('example.com');
				assert.deepEqual([ d.ns[0], d.ttl, d.minimum, d.admin ], [ 'example.com', 60, 30, 'ops.example.net' ]);
				assert.equal(db.setDomainOptions('example.org', { ttl: 5 }), false);
				assert.equal(db.setDomainOptions(7, { ttl: 5 }), false);
			});

			test('are validated', function() {
				db.addDomain('example.com');
				let many = [];
				for (let i = 0; i < 14; i++) {
					many.push('ns' + i + '.example.net');
				}
				for (let bad of [ { ns: 'not valid' }, { ns: [] }, { ns: many }, { ns: [ 'ns.example.net', 7 ] }, { admin: 'not valid' }, { admin: 'a.b@example.com' },
								  { admin: 7 }, { ttl: -1 }, { ttl: 1.5 }, { ttl: '60' }, { refresh: 2147483648 }, { retry: 'x' }, { expiration: {} }, { minimum: [] } ]) {
					assert.throws(() => db.setDomainOptions('example.com', bad), /Invalid domain setting/, JSON.stringify(bad));
					assert.throws(() => db.addDomain('example.org', bad), /Invalid domain setting/, JSON.stringify(bad));
				}
				assert.equal(db.stats().domains, 1);
				assert.deepEqual(Object.keys(db.dump().domains[0]).sort(), [ 'expires', 'lcname', 'name', 'serial' ]);
			});

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
			assert.deepEqual(h.data, full({ a: [ '5.6.7.8' ], aaaa: [], txt: [], mx: [] }));
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

		test('validates every value of an array or a set', function() {
			assert.equal(db.set('h.example.com', { a: [ '1.1.1.1', 'bogus' ] }), false);
			assert.equal(db.set('h.example.com', { aaaa: new Set([ '::1', 7 ]) }), false);
			assert.equal(db.set('h.example.com', { txt: [ 'ok', '' ] }), false);
			assert.equal(db.set('h.example.com', { mx: [ 'mail.example.com', 'not valid' ] }), false);
			assert.equal(db.set('h.example.com', { txt: [ [ 'nested' ] ] }), false);
			assert.equal(db.stats().hosts, 0);
		});

		test('stores values in a normal form', function() {
			db.set('h.example.com', { a: [ '1.2.3.4', '001.002.003.004' ], aaaa: [ '2001:DB8::1', '2001:db8:0:0:0:0:0:1' ], mx: 'MAIL.Example.COM' });
			assert.deepEqual(db.dump().hosts[0].data, full({ a: [ '1.2.3.4' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [], mx: [ 'mail.example.com' ] }));
		});

		test('limits the size of a TXT value and the number of values', function() {
			assert.equal(db.set('h.example.com', { txt: 'x'.repeat(4096) }), true);
			assert.equal(db.set('h.example.com', { txt: 'x'.repeat(4097) }), false);
			let many = [];
			for (let i = 0; i < 101; i++) {
				many.push('10.0.0.' + i);
			}
			assert.equal(db.set('h.example.com', { a: many.slice(0, 100) }), true);
			assert.equal(db.set('h.example.com', { a: many }), false);
			assert.equal(db.set('h.example.com', { a: '10.0.1.1' }, undefined, true), false, 'merge cannot exceed the limit either');
		});

		test('does not keep a reference to a set given by the caller', function() {
			let mine = new Set([ '1.2.3.4' ]);
			db.set('h.example.com', { a: mine });
			mine.add('5.6.7.8');
			assert.deepEqual(db.dump().hosts[0].data.a, [ '1.2.3.4' ]);
		});

		test('stores CNAME, NS, SRV and CAA records', function() {
			assert.equal(db.set('alias.example.com', { cname: 'Target.Example.com.' }), true);
			assert.equal(db.set('sub.example.com', { ns: [ 'ns1.example.net', 'NS2.example.net.' ] }), true);
			assert.equal(db.set('_sip._tcp.example.com', { srv: [ '10 5 5060 sip.example.com', '020 0 5061 SIP2.example.com.' ] }), true);
			assert.equal(db.set('example.com', { caa: [ '0 issue "letsencrypt.org"', '128 IssueWild ;' ] }), true);
			let byName = Object.fromEntries(db.dump().hosts.map((h) => [ h.lcname, h.data ]));
			assert.deepEqual(byName['alias.example.com'].cname, [ 'target.example.com' ]);
			assert.deepEqual(byName['sub.example.com'].ns, [ 'ns1.example.net', 'ns2.example.net' ]);
			assert.deepEqual(byName['_sip._tcp.example.com'].srv, [ '10 5 5060 sip.example.com', '20 0 5061 sip2.example.com' ]);
			assert.deepEqual(byName['example.com'].caa, [ '0 issue letsencrypt.org', '128 issuewild ;' ]);
			assert.deepEqual(db.get('_sip._tcp.example.com', T.SRV).map((r) => [ r.priority, r.weight, r.port, r.target ]),
							 [ [ 10, 5, 5060, 'sip.example.com' ], [ 20, 0, 5061, 'sip2.example.com' ] ]);
			assert.deepEqual(db.get('example.com', T.CAA).map((r) => [ r.flags, r.tag, r.value ]),
							 [ [ 0, 'issue', 'letsencrypt.org' ], [ 128, 'issuewild', ';' ] ]);
			assert.deepEqual(db.get('alias.example.com', T.CNAME).map((r) => r.domain), [ 'target.example.com' ]);
		});

		test('refuses malformed CNAME, NS, SRV and CAA values', function() {
			for (let bad of [ { cname: 'not valid' }, { cname: [ 'a.example.com', 'b.example.com' ] }, { ns: 'x' },
							  { srv: '10 5 sip.example.com' }, { srv: '10 5 70000 sip.example.com' }, { srv: '10 5 5060 not_valid' }, { srv: 7 },
							  { caa: 'issue letsencrypt.org' }, { caa: '256 issue x' }, { caa: '0 bad-tag x' }, { caa: '0 issue ' + 'x'.repeat(256) }, { caa: 7 } ]) {
				assert.equal(db.set('h.example.com', bad), false, JSON.stringify(bad));
			}
		});

		test('an alias has no other records and cannot be the top of a domain', function() {
			assert.equal(db.set('h.example.com', { cname: 'x.example.com', a: '1.2.3.4' }), false);
			assert.equal(db.set('example.com', { cname: 'x.example.com' }), false);
			db.set('h.example.com', { a: '1.2.3.4' });
			assert.equal(db.set('h.example.com', { cname: 'x.example.com' }, undefined, true), false, 'merge would leave the A record');
			assert.equal(db.set('h.example.com', { cname: 'x.example.com' }), true, 'replacing is fine');
			assert.equal(db.set('h.example.com', { txt: 'x' }, undefined, true), false);
			assert.equal(db.set('example.com', { ns: 'ns.example.net' }), false, 'the name servers of a domain are a setting of the domain');
		});

		test('an MX value can carry a priority', function() {
			assert.equal(db.set('h.example.com', { mx: [ 'first.example.com', '5 Second.example.com.', 'third.example.com', '65535 last.example.com' ] }), true);
			assert.deepEqual(db.get('h.example.com', T.MX).map((r) => [ r.exchange, r.priority ]),
							 [ [ 'first.example.com', 1 ], [ 'second.example.com', 5 ], [ 'third.example.com', 3 ], [ 'last.example.com', 65535 ] ]);
			assert.equal(db.set('h.example.com', { mx: '65536 x.example.com' }), false);
			assert.equal(db.set('h.example.com', { mx: '-1 x.example.com' }), false);
			assert.equal(db.set('h.example.com', { mx: '10  x.example.com extra' }), false);
		});

		test('a host may sit at the apex of a domain', function() {
			assert.equal(db.set('example.com', { a: '1.2.3.4' }), true);
		});

		test('replaces all records without merge', function() {
			db.set('h.example.com', { a: '1.2.3.4', txt: 'hello' });
			db.set('h.example.com', { aaaa: '2001:db8::1' });
			assert.deepEqual(db.dump().hosts[0].data, full({ a: [], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [], mx: [] }));
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

		test('hosts expire in order and each expiry advances the serial', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				let events = [];
				d.on('remove', (n) => events.push(n));
				d.addDomain('example.com');
				d.set('c.example.com', { a: '1.2.3.4' }, 3000);
				d.set('a.example.com', { a: '1.2.3.4' }, 1000);
				d.set('b.example.com', { a: '1.2.3.4' }, 2000);
				d.set('never.example.com', { a: '1.2.3.4' });
				let serial = d.get('example.com', T.SOA)[0].serial;
				t.mock.timers.tick(1000);
				assert.deepEqual(events, [ 'a.example.com' ]);
				assert.equal(d.get('example.com', T.SOA)[0].serial, serial + 1);
				t.mock.timers.tick(1000);
				assert.deepEqual(events, [ 'a.example.com', 'b.example.com' ]);
				t.mock.timers.tick(1000);
				assert.deepEqual(events, [ 'a.example.com', 'b.example.com', 'c.example.com' ]);
				t.mock.timers.tick(10000000);
				assert.equal(d.stats().hosts, 1);
			} finally {
				d.close();
				t.mock.timers.reset();
			}
		});

		test('a lifetime can be longer than the longest timer', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				let day = 86400000;
				d.addDomain('example.com');
				assert.equal(d.set('h.example.com', { a: '1.2.3.4' }, 40 * day), true);
				t.mock.timers.tick(39 * day);
				assert.equal(d.stats().hosts, 1);
				t.mock.timers.tick(day);
				assert.equal(d.stats().hosts, 0);
			} finally {
				d.close();
				t.mock.timers.reset();
			}
		});

		test('removing or replacing the next host to expire does not disturb the others', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				d.addDomain('example.com');
				d.set('a.example.com', { a: '1.2.3.4' }, 1000);
				d.set('b.example.com', { a: '1.2.3.4' }, 2000);
				d.remove('a.example.com');
				d.set('b.example.com', { a: '1.2.3.4' }, 5000);
				t.mock.timers.tick(4999);
				assert.equal(d.stats().hosts, 1);
				t.mock.timers.tick(1);
				assert.equal(d.stats().hosts, 0);
			} finally {
				d.close();
				t.mock.timers.reset();
			}
		});

		test('close stops expiry', function(t) {
			t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
			let d = new NameDB();
			try {
				d.addDomain('example.com');
				d.set('a.example.com', { a: '1.2.3.4' }, 1000);
				d.close();
				t.mock.timers.tick(5000);
				assert.equal(d.stats().hosts, 1);
			} finally {
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
			let r = db.lookup('bad_name.example.com', T.A);
			assert.equal(r.rcode, 3);
			assert.deepEqual(r.answers, []);
			r = db.lookup('h.example.com', 65);
			assert.equal(r.rcode, 0);
			assert.deepEqual(r.answers, []);
			assert.equal(db.lookup('h.example.com', T.A).answers.length, 2);
		});

		describe('lookup', function() {

			function soaOf(r) {
				assert.equal(r.authorities.length, 1);
				assert.equal(r.authorities[0].type, T.SOA);
				return r.authorities[0];
			}

			test('an answer is authoritative and has no authority section', function() {
				let r = db.lookup('h.example.com', T.A);
				assert.deepEqual([ r.rcode, r.aa, r.answers.length, r.authorities.length, r.additionals.length ], [ 0, true, 2, 0, 0 ]);
			});

			test('a name that exists without the type gives no data with the SOA', function() {
				let r = db.lookup('h.example.com', T.SRV);
				assert.deepEqual([ r.rcode, r.aa, r.answers.length ], [ 0, true, 0 ]);
				let soa = soaOf(r);
				assert.equal(soa.name, 'example.com');
				assert.equal(soa.ttl, 10, 'the smaller of the record ttl and the SOA minimum');
				assert.equal(db.lookup('example.com', T.A).rcode, 0, 'the top of the domain exists');
				assert.equal(db.lookup('h.example.com', 65).rcode, 0);
			});

			test('a name that does not exist gives NXDOMAIN with the SOA', function() {
				let r = db.lookup('nothing.example.com', T.A);
				assert.deepEqual([ r.rcode, r.aa, r.answers.length ], [ 3, true, 0 ]);
				assert.equal(soaOf(r).serial, db.getDomain('example.com').serial);
				assert.equal(db.lookup('deep.below.h.example.com', T.A).rcode, 3);
			});

			test('the ttl of a negative answer follows the settings', function() {
				db.setDomainOptions('example.com', { ttl: 30, minimum: 3600 });
				assert.equal(soaOf(db.lookup('nothing.example.com', T.A)).ttl, 30);
				db.setDomainOptions('example.com', { ttl: 3600, minimum: 120 });
				assert.equal(soaOf(db.lookup('nothing.example.com', T.A)).ttl, 120);
			});

			test('a name with hosts below it exists', function() {
				db.set('a.b.c.example.com', { a: '1.2.3.4' });
				db.set('x.b.c.example.com', { a: '1.2.3.4' });
				assert.equal(db.lookup('b.c.example.com', T.A).rcode, 0);
				assert.equal(db.lookup('c.example.com', T.A).rcode, 0);
				assert.equal(db.lookup('z.c.example.com', T.A).rcode, 3);
				db.remove('a.b.c.example.com');
				assert.equal(db.lookup('b.c.example.com', T.A).rcode, 0, 'one host is still below');
				db.remove('x.b.c.example.com');
				assert.equal(db.lookup('b.c.example.com', T.A).rcode, 3);
				assert.equal(db.lookup('c.example.com', T.A).rcode, 3);
			});

			test('hosts that expire or go with their domain stop holding names up', function(t) {
				t.mock.timers.enable({ apis: [ 'setTimeout', 'setInterval', 'Date' ] });
				let d = new NameDB();
				try {
					d.addDomain('example.com');
					d.set('a.b.example.com', { a: '1.2.3.4' }, 1000);
					assert.equal(d.lookup('b.example.com', T.A).rcode, 0);
					t.mock.timers.tick(1000);
					assert.equal(d.lookup('b.example.com', T.A).rcode, 3);
					d.set('a.b.example.com', { a: '1.2.3.4' });
					d.removeDomain('example.com');
					d.addDomain('example.com');
					assert.equal(d.lookup('b.example.com', T.A).rcode, 3);
					d.set('a.b.example.com', { a: '1.2.3.4' });
					d.flush();
					d.addDomain('example.com');
					assert.equal(d.lookup('b.example.com', T.A).rcode, 3);
				} finally {
					d.close();
					t.mock.timers.reset();
				}
			});

			test('the name servers of the domain come with their addresses', function() {
				db.setDomainOptions('example.com', { ns: [ 'ns1.example.com', 'ns.elsewhere.net' ] });
				db.set('ns1.example.com', { a: '192.0.2.1', aaaa: '2001:db8::53' });
				let r = db.lookup('example.com', T.NS);
				assert.deepEqual(r.answers.map((x) => x.ns), [ 'ns1.example.com', 'ns.elsewhere.net' ]);
				assert.deepEqual(r.additionals.map((x) => [ x.name, x.type, x.address ]),
								 [ [ 'ns1.example.com', T.A, '192.0.2.1' ], [ 'ns1.example.com', T.AAAA, '2001:db8:0:0:0:0:0:53' ] ]);
			});

			test('an alias answers for every type, with the records of its target', function() {
				db.set('alias.example.com', { cname: 'h.example.com' });
				let r = db.lookup('alias.example.com', T.A);
				assert.deepEqual([ r.rcode, r.aa ], [ 0, true ]);
				assert.deepEqual(r.answers.map((x) => [ x.name, x.type, x.domain ?? x.address ]),
								 [ [ 'alias.example.com', T.CNAME, 'h.example.com' ], [ 'h.example.com', T.A, '1.2.3.4' ], [ 'h.example.com', T.A, '5.6.7.8' ] ]);
				r = db.lookup('alias.example.com', T.CNAME);
				assert.deepEqual(r.answers.map((x) => x.domain), [ 'h.example.com' ]);
				r = db.lookup('alias.example.com', T.SRV);
				assert.deepEqual(r.answers.map((x) => x.type), [ T.CNAME ], 'the target has no SRV records');
			});

			test('aliases are followed through a chain, out of the served domains, and not forever', function() {
				db.set('one.example.com', { cname: 'two.example.com' });
				db.set('two.example.com', { cname: 'h.example.com' });
				assert.deepEqual(db.lookup('one.example.com', T.AAAA).answers.map((x) => x.type), [ T.CNAME, T.CNAME, T.AAAA ]);
				db.set('out.example.com', { cname: 'www.example.org' });
				assert.deepEqual(db.lookup('out.example.com', T.A).answers.map((x) => x.domain), [ 'www.example.org' ]);
				db.set('loop1.example.com', { cname: 'loop2.example.com' });
				db.set('loop2.example.com', { cname: 'loop1.example.com' });
				let r = db.lookup('loop1.example.com', T.A);
				assert.equal(r.rcode, 0);
				assert.ok((r.answers.length > 1) && (r.answers.length < 20));
			});

			test('a delegated name and everything below it is referred to its name servers', function() {
				db.set('sub.example.com', { ns: [ 'ns.sub.example.com', 'ns.example.net' ] });
				db.set('ns.sub.example.com', { a: '192.0.2.53' });
				for (let name of [ 'sub.example.com', 'www.sub.example.com', 'a.b.c.sub.example.com', 'ns.sub.example.com' ]) {
					for (let type of [ T.A, T.NS, T.SOA, 65 ]) {
						let r = db.lookup(name, type);
						assert.deepEqual([ r.rcode, r.aa, r.answers.length ], [ 0, false, 0 ], name);
						assert.deepEqual(r.authorities.map((x) => [ x.name, x.type, x.ns ]),
										 [ [ 'sub.example.com', T.NS, 'ns.sub.example.com' ], [ 'sub.example.com', T.NS, 'ns.example.net' ] ]);
						assert.deepEqual(r.additionals.map((x) => [ x.name, x.address ]), [ [ 'ns.sub.example.com', '192.0.2.53' ] ]);
					}
				}
				let r = db.lookup('sub.example.com', 43);
				assert.deepEqual([ r.rcode, r.aa, r.answers.length, r.authorities[0].type ], [ 0, true, 0, T.SOA ], 'DS belongs to the parent side');
				assert.equal(db.lookup('h.example.com', T.A).aa, true, 'names outside the delegation are not affected');
			});

			test('the delegation nearest to the top of the domain counts', function() {
				db.set('deep.sub.example.com', { ns: 'ns.deep.example.net' });
				db.set('sub.example.com', { ns: 'ns.sub.example.net' });
				assert.deepEqual(db.lookup('x.deep.sub.example.com', T.A).authorities.map((x) => x.ns), [ 'ns.sub.example.net' ]);
			});

			test('names that are not strings or are too long are outside', function() {
				assert.equal(db.lookup(undefined, T.A), false);
				assert.equal(db.lookup('a.'.repeat(130) + 'example.com', T.A), false);
			});

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

		test('a serial given to addDomain is continued, not restarted', function() {
			let now = db.get('example.com', T.SOA)[0].serial;
			db.addDomain('ahead.test', { serial: now + 100000 });
			assert.equal(db.get('ahead.test', T.SOA)[0].serial, now + 100000);
			// A serial that is behind the clock, or unusable, gives way
			// to the time based one.
			db.addDomain('fresh.test');
			let fresh = db.get('fresh.test', T.SOA)[0].serial;
			for (let [ name, serial ] of [ [ 'behind.test', 5 ], [ 'junk.test', 'x' ], [ 'zero.test', 0 ], [ 'huge.test', 4294967296 ] ]) {
				db.addDomain(name, { serial: serial });
				assert.ok(Math.abs(db.get(name, T.SOA)[0].serial - fresh) < 1000, name);
			}
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
