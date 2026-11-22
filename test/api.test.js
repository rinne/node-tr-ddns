'use strict';

const { test, describe, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { once } = require('node:events');

const { lib, startStack, captureConsole, freeTcpPort, full } = require('./helpers');

const pkg = require('../package.json');

function ok(r) {
	assert.equal(r.status, 200, r.text);
	assert.equal(r.body.status, 'ok');
	assert.equal(r.body.code, 200);
	return r.body.data;
}

function bad(r, message, code) {
	assert.equal(r.status, code ?? 400, r.text);
	assert.equal(r.body.status, 'error');
	assert.equal(r.body.code, code ?? 400);
	if (message !== undefined) {
		assert.equal(r.body.message, message);
	}
}

describe('HTTP API', function() {

	let s;

	async function host(name) {
		let d = ok(await s.call('/dump'));
		return d.hosts.find((h) => (h.lcname === name));
	}

	before(async function() {
		s = await startStack();
	});

	after(async function() {
		await s.close();
	});

	beforeEach(async function() {
		s.db.flush();
		s.db.addDomain('example.com');
	});

	test('/ identifies the package', async function() {
		let d = ok(await s.call('/'));
		assert.deepEqual(d, { 'package': 'tr-ddns', version: pkg.version });
	});

	test('responses are JSON and not cacheable', async function() {
		let r = await s.call('/');
		assert.match(r.headers.get('content-type'), /^application\/json/);
		assert.match(r.headers.get('cache-control'), /no-store/);
	});

	test('unknown paths give 404 in the response envelope', async function() {
		bad(await s.call('/nope'), 'Not found', 404);
		bad(await s.call('/host/extra'), 'Not found', 404);
	});

	test('every call works as GET with query and as POST with JSON', async function() {
		ok(await s.call('/host', { host: 'g.example.com', a: '1.2.3.4' }));
		ok(await s.call('/host', { host: 'p.example.com', a: '1.2.3.4' }, { json: true }));
		assert.deepEqual((await host('g.example.com')).data.a, [ '1.2.3.4' ]);
		assert.deepEqual((await host('p.example.com')).data.a, [ '1.2.3.4' ]);
	});

	test('a form encoded POST body works too', async function() {
		ok(await s.call('/host', undefined, { method: 'POST', rawBody: 'host=f.example.com&a=1.2.3.4', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }));
		assert.deepEqual((await host('f.example.com')).data.a, [ '1.2.3.4' ]);
	});

	describe('/domain', function() {

		test('adds and removes domains', async function() {
			ok(await s.call('/domain', { domain: 'Example.ORG' }));
			assert.equal(s.db.stats().domains, 2);
			ok(await s.call('/domain', { domain: 'example.org', remove: 'true' }));
			assert.equal(s.db.stats().domains, 1);
		});

		test('remove may be given as false or as a JSON boolean', async function() {
			ok(await s.call('/domain', { domain: 'example.org', remove: 'false' }));
			ok(await s.call('/domain', { domain: 'example.org', remove: true }, { json: true }));
			assert.equal(s.db.stats().domains, 1);
		});

		test('removing a domain that is not served is not an error', async function() {
			ok(await s.call('/domain', { domain: 'example.net', remove: 'true' }));
		});

		test('removing a domain removes its hosts', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			ok(await s.call('/domain', { domain: 'example.com', remove: 'true' }));
			assert.deepEqual(ok(await s.call('/dump')), { hosts: [], domains: [] });
		});

		test('a domain can be added with settings', async function() {
			ok(await s.call('/domain', { domain: 'example.org', ns: [ 'ns1.example.net', 'ns2.example.net' ], admin: 'hostmaster@example.org',
										 ttl: '300', refresh: '3600', retry: '600', expiration: '604800', minimum: '120' }));
			let d = ok(await s.call('/dump')).domains.find((x) => (x.lcname === 'example.org'));
			assert.deepEqual([ d.ns, d.admin, d.ttl, d.refresh, d.retry, d.expiration, d.minimum ],
							 [ [ 'ns1.example.net', 'ns2.example.net' ], 'hostmaster.example.org', 300, 3600, 600, 604800, 120 ]);
			ok(await s.call('/domain', { domain: 'example.net', ns: 'ns.example.net', ttl: 120 }, { json: true }));
			assert.deepEqual(s.db.getDomain('example.net').ns, [ 'ns.example.net' ]);
			assert.equal(s.db.getDomain('example.net').ttl, 120);
		});

		test('update=true changes the settings of a served domain', async function() {
			ok(await s.call('/domain', { domain: 'example.com', update: 'true', ttl: '120', ns: 'ns.example.net' }));
			assert.equal(s.db.getDomain('example.com').ttl, 120);
			ok(await s.call('/domain', { domain: 'example.com', update: 'true', minimum: '30' }));
			let d = s.db.getDomain('example.com');
			assert.deepEqual([ d.ttl, d.minimum, d.ns[0] ], [ 120, 30, 'ns.example.net' ]);
			ok(await s.call('/domain', { domain: 'example.com', update: 'true', ttl: '', ns: '' }));
			d = s.db.getDomain('example.com');
			assert.deepEqual([ d.ttl, d.minimum, d.ns[0] ], [ 60, 30, 'example.com' ]);
			ok(await s.call('/domain', { domain: 'example.com', update: true }, { json: true }));
		});

		test('ensure=true adds a domain only if it is not served', async function() {
			ok(await s.call('/domain', { domain: 'example.org', ensure: 'true', ttl: '300' }));
			ok(await s.call('/domain', { domain: 'example.org', ensure: 'true' }));
			assert.equal(s.db.getDomain('example.org').ttl, 300, 'a repeat without settings changes nothing');
			ok(await s.call('/domain', { domain: 'example.org', ensure: true, minimum: 30 }, { json: true }));
			let d = s.db.getDomain('example.org');
			assert.deepEqual([ d.ttl, d.minimum ], [ 300, 30 ]);
			let serial = s.db.getDomain('example.com').serial;
			ok(await s.call('/domain', { domain: 'example.com', ensure: 'true' }));
			assert.equal(s.db.getDomain('example.com').serial, serial);
			bad(await s.call('/domain', { domain: 'sub.example.com', ensure: 'true' }), 'Bad request (unable to add domain)');
			bad(await s.call('/domain', { domain: 'example.com', ensure: 'true', remove: 'true' }), 'Bad request (conflicting params)');
			bad(await s.call('/domain', { domain: 'example.com', ensure: 'true', update: 'true' }), 'Bad request (conflicting params)');
			bad(await s.call('/domain', { domain: 'example.com', ensure: 'maybe' }), 'Bad request (ensure)');
			bad(await s.call('/domain', { domain: 'example.com', ensure: 'true', ttl: 'x' }), 'Bad request (ttl)');
		});

		test('rejects bad settings', async function() {
			bad(await s.call('/domain', { domain: 'example.org', ns: 'not valid' }), 'Bad request (ns)');
			bad(await s.call('/domain', { domain: 'example.org', ns: [ 'ns.example.net', 'x' ] }), 'Bad request (ns)');
			bad(await s.call('/domain', { domain: 'example.org', admin: 'not valid' }), 'Bad request (admin)');
			bad(await s.call('/domain', { domain: 'example.org', admin: [ 'a.b', 'c.d' ] }), 'Bad request (admin)');
			bad(await s.call('/domain', { domain: 'example.org', ttl: 'long' }), 'Bad request (ttl)');
			bad(await s.call('/domain', { domain: 'example.org', ttl: '-1' }), 'Bad request (ttl)');
			bad(await s.call('/domain', { domain: 'example.org', refresh: '99999999999' }), 'Bad request (refresh)');
			bad(await s.call('/domain', { domain: 'example.org', retry: 1.5 }, { json: true }), 'Bad request (retry)');
			bad(await s.call('/domain', { domain: 'example.org', expiration: true }, { json: true }), 'Bad request (expiration)');
			bad(await s.call('/domain', { domain: 'example.org', minimum: [ '1', '2' ] }), 'Bad request (minimum)');
			bad(await s.call('/domain', { domain: 'example.com', update: 'true', admin: 'not valid' }), 'Bad request (admin)');
			bad(await s.call('/domain', { domain: 'example.org', update: 'true', ttl: '5' }), 'Bad request (unable to update domain)');
			bad(await s.call('/domain', { domain: 'example.com', update: 'maybe' }), 'Bad request (update)');
			bad(await s.call('/domain', { domain: 'example.com', remove: 'true', ttl: '5' }), 'Bad request (conflicting params)');
			bad(await s.call('/domain', { domain: 'example.com', remove: 'true', update: 'true' }), 'Bad request (conflicting params)');
			assert.equal(s.db.stats().domains, 1);
		});

		test('rejects bad requests', async function() {
			bad(await s.call('/domain'), 'Bad request (domain)');
			bad(await s.call('/domain', { domain: 'not valid' }), 'Bad request (domain)');
			bad(await s.call('/domain', { domain: 'example.com' }), 'Bad request (unable to add domain)');
			bad(await s.call('/domain', { domain: 'sub.example.com' }), 'Bad request (unable to add domain)');
			bad(await s.call('/domain', { domain: 'com' }), 'Bad request (unable to add domain)');
			bad(await s.call('/domain', { domain: 'example.org', remove: 'maybe' }), 'Bad request (remove)');
		});

	});

	describe('/host', function() {

		test('sets all record types at once', async function() {
			ok(await s.call('/host', { host: 'H.example.com', a: '1.2.3.4', aaaa: '2001:db8::1', txt: 'hello', mx: 'mail.example.com' }));
			let h = await host('h.example.com');
			assert.equal(h.name, 'H.example.com');
			assert.deepEqual(h.data, full({ a: [ '1.2.3.4' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [ 'mail.example.com' ] }));
			assert.equal(h.expires, null);
		});

		test('a second call replaces all records', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', txt: 'hello' }));
			ok(await s.call('/host', { host: 'h.example.com', aaaa: '2001:db8::1' }));
			assert.deepEqual((await host('h.example.com')).data, full({ a: [], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [], mx: [] }));
		});

		test('merge keeps the records that are not mentioned', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', txt: 'hello' }));
			ok(await s.call('/host', { host: 'h.example.com', aaaa: '2001:db8::1', merge: 'true' }));
			let d = (await host('h.example.com')).data;
			assert.deepEqual(d.a, [ '1.2.3.4' ]);
			assert.deepEqual(d.txt, [ 'hello' ]);
			assert.deepEqual(d.aaaa, [ '2001:db8:0:0:0:0:0:1' ]);
		});

		test('merge with an empty value removes that record type', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', txt: 'hello' }));
			ok(await s.call('/host', { host: 'h.example.com', txt: '', merge: 'true' }));
			let d = (await host('h.example.com')).data;
			assert.deepEqual(d.a, [ '1.2.3.4' ]);
			assert.deepEqual(d.txt, []);
		});

		test('ttl sets a lifetime in seconds for the whole host', async function() {
			let t0 = Date.now();
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '3600' }));
			let h = await host('h.example.com');
			assert.ok((h.expires >= (t0 + 3600000)) && (h.expires <= (Date.now() + 3600000)));
			ok(await s.call('/host', { host: 'j.example.com', a: '1.2.3.4', ttl: 60 }, { json: true }));
			assert.equal(typeof((await host('j.example.com')).expires), 'number');
		});

		test('a call without ttl makes the host permanent again', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '3600' }));
			ok(await s.call('/host', { host: 'h.example.com', txt: 'x', merge: 'true' }));
			assert.equal((await host('h.example.com')).expires, null);
		});

		test('remove=true removes the host', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			ok(await s.call('/host', { host: 'h.example.com', remove: 'true' }));
			assert.equal(await host('h.example.com'), undefined);
		});

		test('ensure=true lets a removal succeed when there is no such host', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			ok(await s.call('/host', { host: 'h.example.com', remove: 'true', ensure: 'true' }));
			ok(await s.call('/host', { host: 'h.example.com', remove: 'true', ensure: 'true' }));
			ok(await s.call('/host', { host: 'h.example.com', ensure: 'true' }), 'a call without records is a removal');
			bad(await s.call('/host', { host: 'h.example.org', remove: 'true', ensure: 'true' }), 'Bad request (unable to remove host)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ensure: 'true' }), 'Bad request (conflicting params)');
			bad(await s.call('/host', { host: 'h.example.com', remove: 'true', ensure: 'maybe' }), 'Bad request (ensure)');
		});

		test('a call without any record removes the host', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			ok(await s.call('/host', { host: 'h.example.com' }));
			assert.equal(await host('h.example.com'), undefined);
		});

		test('rejects bad requests', async function() {
			bad(await s.call('/host'), 'Bad request (host)');
			bad(await s.call('/host', { host: 'not valid', a: '1.2.3.4' }), 'Bad request (host)');
			bad(await s.call('/host', { host: 'h.example.com', a: 'bogus' }), 'Bad request (a)');
			bad(await s.call('/host', { host: 'h.example.com', aaaa: '1.2.3.4' }), 'Bad request (aaaa)');
			bad(await s.call('/host', { host: 'h.example.com', txt: 7 }, { json: true }), 'Bad request (txt)');
			bad(await s.call('/host', { host: 'h.example.com', mx: 'not valid' }), 'Bad request (mx)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '0' }), 'Bad request (ttl)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: 'soon' }), 'Bad request (ttl)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', remove: 'maybe' }), 'Bad request (remove)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', merge: 'maybe' }), 'Bad request (merge)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', remove: 'true' }), 'Bad request (conflicting params)');
			bad(await s.call('/host', { host: 'h.example.org', a: '1.2.3.4' }), 'Bad request (unable to add/update host)');
			bad(await s.call('/host', { host: 'h.example.com', remove: 'true' }), 'Bad request (unable to remove host)');
			assert.equal(s.db.stats().hosts, 0);
		});

		test('several values of a type can be given at once', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: [ '1.2.3.4', '5.6.7.8' ], txt: [ 'one', 'two' ] }));
			assert.deepEqual((await host('h.example.com')).data, full({ a: [ '1.2.3.4', '5.6.7.8' ], aaaa: [], txt: [ 'one', 'two' ], mx: [] }));
			ok(await s.call('/host', { host: 'j.example.com', aaaa: [ '2001:db8::1', '2001:db8::2' ] }, { json: true }));
			assert.equal((await host('j.example.com')).data.aaaa.length, 2);
			bad(await s.call('/host', { host: 'h.example.com', a: [ '1.2.3.4', 'bogus' ] }), 'Bad request (a)');
			bad(await s.call('/host', { host: 'h.example.com', a: [] }, { json: true }), 'Bad request (a)');
		});

		test('values of the wrong shape are refused, not stored', async function() {
			for (let v of [ { x: 1 }, 7, true, [ [ '1.2.3.4' ] ] ]) {
				bad(await s.call('/host', { host: 'h.example.com', a: v }, { json: true }), 'Bad request (a)');
			}
			bad(await s.call('/host', { host: [ 'h.example.com', 'j.example.com' ], a: '1.2.3.4' }), 'Bad request (host)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: [ '60', '70' ] }), 'Bad request (ttl)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: true }, { json: true }), 'Bad request (ttl)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: 0.0001 }, { json: true }), 'Bad request (ttl)');
			bad(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', merge: [ 'true' ] }, { json: true }), 'Bad request (merge)');
			bad(await s.call('/host', { host: 'h.example.com', txt: 'x'.repeat(5000) }, { json: true }), 'Bad request (txt)');
			assert.equal(s.db.stats().hosts, 0);
		});

		test('a lifetime can be longer than 24 days', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '31536000' }));
			let h = await host('h.example.com');
			assert.ok(Math.abs(h.expires - (Date.now() + 31536000000)) < 5000);
		});

		test('sets CNAME, NS, SRV and CAA records', async function() {
			ok(await s.call('/host', { host: 'alias.example.com', cname: 'target.example.com' }));
			ok(await s.call('/host', { host: 'sub.example.com', ns: [ 'ns1.example.net', 'ns2.example.net' ] }));
			ok(await s.call('/host', { host: '_sip._tcp.example.com', srv: '10 5 5060 sip.example.com' }));
			ok(await s.call('/host', { host: 'example.com', caa: '0 issue "letsencrypt.org"', mx: '10 mail.example.com' }));
			assert.deepEqual((await host('alias.example.com')).data.cname, [ 'target.example.com' ]);
			assert.deepEqual((await host('sub.example.com')).data.ns, [ 'ns1.example.net', 'ns2.example.net' ]);
			assert.deepEqual((await host('_sip._tcp.example.com')).data.srv, [ '10 5 5060 sip.example.com' ]);
			assert.deepEqual((await host('example.com')).data.caa, [ '0 issue letsencrypt.org' ]);
			assert.deepEqual((await host('example.com')).data.mx, [ '10 mail.example.com' ]);
			bad(await s.call('/host', { host: 'h.example.com', cname: 'not valid' }), 'Bad request (cname)');
			bad(await s.call('/host', { host: 'h.example.com', srv: 'nope' }), 'Bad request (srv)');
			bad(await s.call('/host', { host: 'h.example.com', caa: 'nope' }), 'Bad request (caa)');
			bad(await s.call('/host', { host: 'h.example.com', ns: 'nope' }), 'Bad request (ns)');
			bad(await s.call('/host', { host: 'h.example.com', cname: 'x.example.com', a: '1.2.3.4' }), 'Bad request (unable to add/update host)');
			bad(await s.call('/host', { host: 'alias.example.com', cname: 'x.example.com', remove: 'true' }), 'Bad request (conflicting params)');
		});

		test('a host name may end with a dot and have underscore labels', async function() {
			ok(await s.call('/host', { host: 'selector._domainkey.example.com.', txt: 'v=DKIM1' }));
			assert.equal((await host('selector._domainkey.example.com')).name, 'selector._domainkey.example.com');
			ok(await s.call('/host', { host: 'selector._domainkey.example.com', remove: 'true' }));
		});

		test('remove conflicts with mx as with the other records', async function() {
			bad(await s.call('/host', { host: 'h.example.com', mx: 'mail.example.com', remove: 'true' }), 'Bad request (conflicting params)');
		});

	});

	describe('/record', function() {

		test('adds, sets, removes and clears single values', async function() {
			let c = (command, type, value) => s.call('/record', { host: 'h.example.com', command, type, value });
			ok(await c('add', 'a', '1.2.3.4'));
			ok(await c('add', 'a', '5.6.7.8'));
			ok(await c('add', 'aaaa', '2001:db8::1'));
			ok(await c('add', 'txt', 'one'));
			ok(await c('add', 'txt', 'two'));
			ok(await c('add', 'mx', 'Mail.example.com'));
			assert.deepEqual((await host('h.example.com')).data,
							 full({ a: [ '1.2.3.4', '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'one', 'two' ], mx: [ 'mail.example.com' ] }));
			ok(await c('remove', 'a', '1.2.3.4'));
			ok(await c('set', 'txt', 'three'));
			ok(await s.call('/record', { host: 'h.example.com', command: 'clear', type: 'mx' }));
			assert.deepEqual((await host('h.example.com')).data,
							 full({ a: [ '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'three' ], mx: [] }));
		});

		test('works for every record type', async function() {
			let c = (host, command, type, value) => s.call('/record', { host, command, type, value });
			ok(await c('_sip._tcp.example.com', 'add', 'srv', '10 5 5060 sip.example.com'));
			ok(await c('_sip._tcp.example.com', 'add', 'srv', '20 5 5060 sip2.example.com'));
			ok(await c('_sip._tcp.example.com', 'remove', 'srv', '10  5  5060  SIP.example.com'));
			assert.deepEqual((await host('_sip._tcp.example.com')).data.srv, [ '20 5 5060 sip2.example.com' ]);
			ok(await c('example.com', 'add', 'caa', '0 issue letsencrypt.org'));
			ok(await c('alias.example.com', 'set', 'cname', 'a.example.com'));
			ok(await c('alias.example.com', 'set', 'cname', 'b.example.com'));
			assert.deepEqual((await host('alias.example.com')).data.cname, [ 'b.example.com' ]);
			bad(await c('alias.example.com', 'add', 'cname', 'c.example.com'), 'Bad request (unable to add/update host)');
			bad(await c('alias.example.com', 'add', 'a', '1.2.3.4'), 'Bad request (unable to add/update host)');
			ok(await c('sub.example.com', 'add', 'ns', 'ns.example.net'));
			ok(await c('mail.example.com', 'add', 'mx', '10 mx.example.com'));
			assert.deepEqual((await host('mail.example.com')).data.mx, [ '10 mx.example.com' ]);
		});

		test('creates the host when it does not exist', async function() {
			ok(await s.call('/record', { host: 'new.example.com', command: 'add', type: 'a', value: '1.2.3.4' }));
			assert.deepEqual((await host('new.example.com')).data.a, [ '1.2.3.4' ]);
		});

		test('remove and clear do not create a host', async function() {
			ok(await s.call('/record', { host: 'none.example.com', command: 'remove', type: 'a', value: '1.2.3.4' }));
			ok(await s.call('/record', { host: 'none.example.com', command: 'clear', type: 'txt' }));
			assert.equal(await host('none.example.com'), undefined);
			bad(await s.call('/record', { host: 'none.example.com', command: 'remove', type: 'a', value: 'junk' }), 'Bad request (value)');
		});

		test('rejects bad requests', async function() {
			bad(await s.call('/record', { command: 'add', type: 'a', value: '1.2.3.4' }), 'Bad request (host)');
			bad(await s.call('/record', { host: 'h.example.com', command: 'nope', type: 'a', value: '1.2.3.4' }), 'Bad request (command)');
			bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'bogus', value: 'x.example.com' }), 'Bad request (type)');
			bad(await s.call('/record', { host: 'h.example.org', command: 'add', type: 'a', value: '1.2.3.4' }), 'Bad request (no matching domain)');
		});

		test('an invalid value is rejected with one response and changes nothing', async function() {
			ok(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'a', value: '1.2.3.4' }));
			let serial = (await s.call('/dump')).body.data.domains[0].serial;
			let lines = await captureConsole(async function() {
				bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'a', value: 'bogus' }), 'Bad request (value)');
				bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'aaaa', value: '1.2.3.4' }), 'Bad request (value)');
				bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'txt', value: '' }), 'Bad request (value)');
				bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'mx', value: 'not valid' }), 'Bad request (value)');
			});
			assert.equal(lines.filter((l) => /ERR_HTTP_HEADERS_SENT/.test(l)).length, 0);
			assert.equal((await s.call('/dump')).body.data.domains[0].serial, serial);
		});

		test('keeps the lifetime of the host', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '3600' }));
			let expires = (await host('h.example.com')).expires;
			ok(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'a', value: '5.6.7.8' }));
			let after = (await host('h.example.com')).expires;
			assert.ok((after !== null) && (Math.abs(after - expires) < 1000));
		});

		test('does not print anything', async function() {
			let lines = await captureConsole(async function() {
				ok(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'a', value: '1.2.3.4' }));
			});
			assert.deepEqual(lines, []);
		});

	});

	describe('/dump, /stats and /flush', function() {

		test('/dump returns hosts and domains', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			let d = ok(await s.call('/dump'));
			assert.deepEqual(Object.keys(d).sort(), [ 'domains', 'hosts' ]);
			assert.equal(d.domains[0].name, 'example.com');
			assert.equal(d.hosts[0].name, 'h.example.com');
		});

		test('/stats returns counters', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			let d = ok(await s.call('/stats'));
			assert.equal(d.authFailures, 0);
			assert.deepEqual(Object.keys(d.dns).sort(), [ 'answered', 'dropped', 'empty', 'nxdomain', 'queries', 'refused' ]);
			assert.deepEqual(Object.keys(d.dns.dropped).sort(), [ 'error', 'invalid', 'notQuery', 'outOfZone', 'rateLimited' ]);
			assert.equal(d.domains, 1);
			assert.equal(d.hosts, 1);
			assert.equal(typeof(d.lookup.total), 'number');
			assert.equal(typeof(d.lookup.errors), 'number');
			assert.ok(d.apiCalls >= 2);
		});

		test('/flush removes hosts and domains', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }));
			ok(await s.call('/flush'));
			assert.deepEqual(ok(await s.call('/dump')), { hosts: [], domains: [] });
		});

	});

	describe('request handling of the HTTP layer', function() {

		test('methods other than GET, POST, PUT and DELETE are refused', async function() {
			bad(await s.call('/', undefined, { method: 'PATCH' }), 'Method Not Allowed', 405);
		});

		test('PUT and DELETE reach the handlers like POST and GET', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }, { json: true, method: 'PUT' }));
			ok(await s.call('/host', { host: 'h.example.com' }, { method: 'DELETE' }));
			assert.equal(s.db.stats().hosts, 0);
		});

		test('a POST with query parameters is refused', async function() {
			let r = await s.call('/host?host=h.example.com&a=1.2.3.4', {}, { json: true });
			bad(r);
			assert.match(r.body.message, /^Bad Request \(/);
		});

		test('a body that is not JSON or form encoded is refused', async function() {
			bad(await s.call('/host', undefined, { method: 'POST', rawBody: 'hello', headers: { 'Content-Type': 'text/plain' } }));
			bad(await s.call('/host', undefined, { method: 'POST', rawBody: '{not json', headers: { 'Content-Type': 'application/json' } }));
		});

		test('a request body over the size limit is refused', async function() {
			let r = await s.call('/host', { host: 'h.example.com', txt: 'x'.repeat(70000) }, { json: true });
			bad(r, undefined, 413);
		});

		test('a JSON body must be an object without dangerous keys', async function() {
			bad(await s.call('/host', undefined, { method: 'POST', rawBody: '["h.example.com"]', headers: { 'Content-Type': 'application/json' } }));
			bad(await s.call('/host', undefined, { method: 'POST', rawBody: '{"host":"h.example.com","a":"1.2.3.4","__proto__":{"x":1}}', headers: { 'Content-Type': 'application/json' } }));
			assert.equal(s.db.stats().hosts, 0);
		});

		test('paths with empty or dot segments are refused', async function() {
			bad(await s.call('//host'));
			bad(await s.call('/a//b'));
		});

		test('errors of the HTTP layer are JSON', async function() {
			let r = await s.call('/', undefined, { method: 'PATCH' });
			assert.match(r.headers.get('content-type'), /^application\/json/);
			assert.deepEqual(Object.keys(r.body).sort(), [ 'code', 'message', 'status' ]);
		});

	});

});

describe('HTTP API with authentication', function() {

	let s;

	before(async function() {
		s = await startStack({ api: { basicAuth: Buffer.from('user:secret').toString('base64') } });
	});

	after(async function() {
		await s.close();
	});

	test('refuses calls without credentials', async function() {
		let r = await s.call('/');
		bad(r, 'Unauthorized', 401);
		assert.match(r.headers.get('www-authenticate'), /^Basic realm="TR-DDNS"/);
	});

	test('refuses wrong credentials', async function() {
		bad(await s.call('/', undefined, { auth: 'user:wrong' }), 'Unauthorized', 401);
		bad(await s.call('/', undefined, { auth: 'other:secret' }), 'Unauthorized', 401);
		bad(await s.call('/', undefined, { headers: { Authorization: 'Bearer c2VjcmV0' } }), 'Unauthorized', 401);
		bad(await s.call('/flush', undefined, { auth: 'user:secre' }), 'Unauthorized', 401);
	});

	test('the scheme name is case-insensitive', async function() {
		let b64 = Buffer.from('user:secret').toString('base64');
		for (let scheme of [ 'basic', 'BASIC', 'bAsIc' ]) {
			ok(await s.call('/stats', undefined, { headers: { Authorization: scheme + ' ' + b64 } }), scheme);
		}
	});

	test('credentials are checked before the body is looked at', async function() {
		let r = await s.call('/host', undefined, { method: 'POST', rawBody: '{not json', headers: { 'Content-Type': 'application/json' } });
		bad(r, 'Unauthorized', 401);
		r = await s.call('/host', undefined, { method: 'POST', rawBody: '{not json', headers: { 'Content-Type': 'application/json' }, auth: 'user:secret' });
		bad(r, undefined, 400);
	});

	test('failed attempts are counted', async function() {
		let before = (await s.call('/stats', undefined, { auth: 'user:secret' })).body.data.authFailures;
		await s.call('/');
		await s.call('/', undefined, { auth: 'user:nope' });
		let after = (await s.call('/stats', undefined, { auth: 'user:secret' })).body.data.authFailures;
		assert.equal(after - before, 2);
	});

	test('accepts the right credentials', async function() {
		ok(await s.call('/', undefined, { auth: 'user:secret' }));
		ok(await s.call('/domain', { domain: 'example.com' }, { auth: 'user:secret', json: true }));
	});

});

describe('ApiCore', function() {

	let db, api;

	beforeEach(function() {
		db = new lib.NameDB();
		db.addDomain('example.com');
		api = new lib.ApiCore({ nameDB: db });
	});

	afterEach(function() {
		db.close();
	});

	test('performs a call without any transport', function() {
		assert.deepEqual(api.handle({ path: '/host', params: { host: 'h.example.com', a: '1.2.3.4' } }),
						 { status: 200, body: { status: 'ok', code: 200 } });
		assert.deepEqual(db.dump().hosts[0].data.a, [ '1.2.3.4' ]);
		let r = api.handle({ method: 'GET', path: '/' });
		assert.deepEqual(r, { status: 200, body: { status: 'ok', code: 200, data: { 'package': 'tr-ddns', version: pkg.version } } });
		assert.equal(api.handle({ path: '/dump' }).body.data.hosts.length, 1);
		assert.equal(api.handle({ path: '/flush' }).status, 200);
		assert.equal(db.stats().domains, 0);
	});

	test('answers with a status and a message when a call fails', function() {
		assert.deepEqual(api.handle({ path: '/host', params: { host: 'not valid' } }),
						 { status: 400, body: { status: 'error', code: 400, message: 'Bad request (host)' } });
		assert.deepEqual(api.handle({ path: '/nope' }), { status: 404, body: { status: 'error', code: 404, message: 'Not found' } });
		for (let request of [ undefined, null, {}, { path: 7 }, { path: '/host' }, { path: '/host', params: 'x' }, { path: '/record', params: null } ]) {
			let r = api.handle(request);
			assert.ok([ 400, 404 ].includes(r.status), JSON.stringify(request));
			assert.equal(r.body.code, r.status);
		}
	});

	test('an unexpected failure is a 500 and is logged, not thrown', async function() {
		let broken = new lib.ApiCore({ nameDB: { get: () => [], dump: () => { throw new Error('boom'); } } });
		let r;
		let lines = await captureConsole(() => { r = broken.handle({ path: '/dump' }); });
		assert.deepEqual(r, { status: 500, body: { status: 'error', code: 500, message: 'Internal error' } });
		assert.ok(lines.some((l) => /boom/.test(l)));
	});

	test('counts calls and refused calls for /stats', function() {
		api.countCall();
		api.countCall();
		api.countAuthFailure();
		let d = api.handle({ path: '/stats' }).body.data;
		assert.deepEqual([ d.apiCalls, d.authFailures, d.domains ], [ 2, 1, 1 ]);
		assert.equal(d.dns, undefined);
	});

	test('includes the counters of the servers it is given', function() {
		let withServers = new lib.ApiCore({ nameDB: db, nameServer: { stats: () => ({ queries: 5 }) }, dohServer: { stats: () => ({ requests: 3 }) } });
		let d = withServers.handle({ path: '/stats' }).body.data;
		assert.deepEqual(d.dns, { queries: 5 });
		assert.deepEqual(d.doh, { requests: 3 });
	});

	test('validates its options', function() {
		assert.throws(() => new lib.ApiCore({}), /NameDB/);
		assert.throws(() => new lib.ApiCore({ nameDB: db, nameServer: {} }), /NameServer/);
		assert.throws(() => new lib.ApiCore({ nameDB: db, dohServer: {} }), /DohServer/);
	});

	test('one core can serve several transports', async function() {
		let a = new lib.ApiServer({ api: api, port: await freeTcpPort(), address: '127.0.0.1' });
		await once(a, 'ready');
		try {
			assert.throws(() => new lib.ApiServer({ api: {}, port: 8080 }), /ApiCore/);
		} finally {
			await a.close();
		}
	});

});

describe('HTTP API and web browsers', function() {

	let s;

	before(async function() {
		s = await startStack({ api: { allowedHosts: 'ddns.example.net, Other.Example.NET' } });
		ok(await s.call('/domain', { domain: 'example.com' }));
	});

	after(async function() {
		await s.close();
	});

	// node:http, because fetch does not let the Host header be set.
	function raw(path, headers) {
		return new Promise(function(resolve, reject) {
			let req = require('node:http').request({ host: '127.0.0.1', port: s.apiPort, path: path, headers: headers }, function(res) {
				res.resume();
				res.on('end', () => resolve(res.statusCode));
			});
			req.on('error', reject);
			req.end();
		});
	}

	test('programs that send no browser headers are served', async function() {
		let here = '127.0.0.1:' + s.apiPort;
		for (let host of [ here, 'localhost:' + s.apiPort, 'ddns.example.net', 'other.example.net:8080', '[::1]:8080' ]) {
			assert.equal(await raw('/stats', { Host: host }), 200, host);
		}
		assert.equal(await raw('/stats', { Origin: 'http://' + here, 'Sec-Fetch-Site': 'same-origin' }), 200);
		assert.equal(await raw('/stats', { 'Sec-Fetch-Site': 'none' }), 200, 'typed into the address bar');
		assert.equal(await raw('/stats', { Referer: 'http://' + here + '/x' }), 200);
	});

	test('requests that a browser sends for another site are refused', async function() {
		let here = '127.0.0.1:' + s.apiPort;
		let cases = [
			{ 'Sec-Fetch-Site': 'cross-site' },
			{ 'Sec-Fetch-Site': 'same-site' },
			{ Origin: 'http://evil.example.org' },
			{ Origin: 'http://127.0.0.1:3000' },
			{ Origin: 'null' },
			{ Referer: 'http://evil.example.org/page' },
			{ Referer: 'http://127.0.0.1/page' }
		];
		for (let h of cases) {
			assert.equal(await raw('/host?host=x.example.com&a=192.0.2.1', Object.assign({ Host: here }, h)), 403, JSON.stringify(h));
		}
		assert.equal(await raw('/host?host=x.example.com&a=192.0.2.1', { Host: 'rebound.example.org' }), 403, 'DNS rebinding');
		assert.equal(await raw('/stats', { Host: 'ddns.example.net.evil.org' }), 403);
		let d = ok(await s.call('/dump'));
		assert.equal(d.hosts.length, 0, 'nothing was changed');
		assert.equal(ok(await s.call('/stats')).foreignRefused, cases.length + 2);
	});

	test('validates the allowed hosts', async function() {
		let db = new lib.NameDB();
		try {
			for (let bad of [ 7, [ 'ok.example', 'not valid' ], 'a,-b' ]) {
				assert.throws(() => new lib.ApiServer({ nameDB: db, port: 8080, allowedHosts: bad }), /allowed hosts/, String(bad));
			}
		} finally {
			db.close();
		}
	});

});

describe('ApiServer', function() {

	test('validates its options', async function() {
		let db = new lib.NameDB();
		try {
			assert.throws(() => new lib.ApiServer({ port: 8080 }), /NameDB/);
			assert.throws(() => new lib.ApiServer({ nameDB: db, port: 70000 }), /port/);
			assert.throws(() => new lib.ApiServer({ nameDB: db, port: 8080, address: 'bogus' }), /address/);
		} finally {
			db.close();
		}
	});

	test('reports a port that is in use as an error event', async function() {
		let db = new lib.NameDB();
		let blocker = require('node:net').createServer();
		await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
		let api = new lib.ApiServer({ nameDB: db, port: blocker.address().port, address: '127.0.0.1' });
		try {
			let [ e ] = await once(api, 'error');
			assert.equal(e.code, 'EADDRINUSE');
		} finally {
			await api.close();
			blocker.close();
			db.close();
		}
	});

	test('validates the options added later', function() {
		let db = new lib.NameDB();
		try {
			assert.throws(() => new lib.ApiServer({ nameDB: db, port: 8080, basicAuth: '' }), /basic auth/);
			assert.throws(() => new lib.ApiServer({ nameDB: db, port: 8080, maxBodySize: -1 }), /body size/);
			assert.throws(() => new lib.ApiServer({ nameDB: db, port: 8080, nameServer: {} }), /NameServer/);
		} finally {
			db.close();
		}
	});

	test('close stops the listener', async function() {
		let db = new lib.NameDB();
		let port = await freeTcpPort();
		let api = new lib.ApiServer({ nameDB: db, port: port, address: '127.0.0.1' });
		await once(api, 'ready');
		let base = 'http://127.0.0.1:' + port + '/';
		await api.close();
		await assert.rejects(fetch(base));
		db.close();
	});

});
