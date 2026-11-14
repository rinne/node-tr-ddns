'use strict';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const { lib, startStack, captureConsole, freeTcpPort } = require('./helpers');

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
			assert.deepEqual(h.data, { a: [ '1.2.3.4' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [ 'mail.example.com' ] });
			assert.equal(h.expires, null);
		});

		test('a second call replaces all records', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', txt: 'hello' }));
			ok(await s.call('/host', { host: 'h.example.com', aaaa: '2001:db8::1' }));
			assert.deepEqual((await host('h.example.com')).data, { a: [], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [], mx: [] });
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

		test('remove conflicts with mx as with the other records', { todo: 'Phase 1 item 10' }, async function() {
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
							 { a: [ '1.2.3.4', '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'one', 'two' ], mx: [ 'mail.example.com' ] });
			ok(await c('remove', 'a', '1.2.3.4'));
			ok(await c('set', 'txt', 'three'));
			ok(await s.call('/record', { host: 'h.example.com', command: 'clear', type: 'mx' }));
			assert.deepEqual((await host('h.example.com')).data,
							 { a: [ '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'three' ], mx: [] });
		});

		test('creates the host when it does not exist', async function() {
			ok(await s.call('/record', { host: 'new.example.com', command: 'add', type: 'a', value: '1.2.3.4' }));
			assert.deepEqual((await host('new.example.com')).data.a, [ '1.2.3.4' ]);
		});

		test('rejects bad requests', async function() {
			bad(await s.call('/record', { command: 'add', type: 'a', value: '1.2.3.4' }), 'Bad request (host)');
			bad(await s.call('/record', { host: 'h.example.com', command: 'nope', type: 'a', value: '1.2.3.4' }), 'Bad request (command)');
			bad(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'cname', value: 'x.example.com' }), 'Bad request (type)');
			bad(await s.call('/record', { host: 'h.example.org', command: 'add', type: 'a', value: '1.2.3.4' }), 'Bad request (no matching domain)');
		});

		test('an invalid value is rejected with one response and changes nothing', { todo: 'Phase 1 item 5' }, async function() {
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

		test('keeps the lifetime of the host', { todo: 'Phase 1 item 6' }, async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4', ttl: '3600' }));
			let expires = (await host('h.example.com')).expires;
			ok(await s.call('/record', { host: 'h.example.com', command: 'add', type: 'a', value: '5.6.7.8' }));
			let after = (await host('h.example.com')).expires;
			assert.ok((after !== null) && (Math.abs(after - expires) < 1000));
		});

		test('does not print anything', { todo: 'Phase 1 item 4' }, async function() {
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
			let r = await s.call('/', undefined, { method: 'PATCH' });
			assert.equal(r.status, 405);
		});

		test('PUT and DELETE reach the handlers like POST and GET', async function() {
			ok(await s.call('/host', { host: 'h.example.com', a: '1.2.3.4' }, { json: true, method: 'PUT' }));
			ok(await s.call('/host', { host: 'h.example.com' }, { method: 'DELETE' }));
			assert.equal(s.db.stats().hosts, 0);
		});

		test('a POST with query parameters is refused', async function() {
			let r = await s.call('/host?host=h.example.com&a=1.2.3.4', {}, { json: true });
			assert.equal(r.status, 400);
		});

		test('a body that is not JSON or form encoded is refused', async function() {
			let r = await s.call('/host', undefined, { method: 'POST', rawBody: 'hello', headers: { 'Content-Type': 'text/plain' } });
			assert.equal(r.status, 400);
			r = await s.call('/host', undefined, { method: 'POST', rawBody: '{not json', headers: { 'Content-Type': 'application/json' } });
			assert.equal(r.status, 400);
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

	test('accepts the right credentials', async function() {
		ok(await s.call('/', undefined, { auth: 'user:secret' }));
		ok(await s.call('/domain', { domain: 'example.com' }, { auth: 'user:secret', json: true }));
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

	test('close stops the listener', async function() {
		let db = new lib.NameDB();
		let port = await freeTcpPort();
		let api = new lib.ApiServer({ nameDB: db, port: port, address: '127.0.0.1' });
		let base = 'http://127.0.0.1:' + port + '/';
		for (let i = 0; i < 100; i++) {
			try {
				await fetch(base);
				break;
			} catch (e) {
				await new Promise((r) => setTimeout(r, 20));
			}
		}
		await api.close();
		await assert.rejects(fetch(base));
		db.close();
	});

});
