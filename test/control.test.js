'use strict';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { once } = require('node:events');

const { lib, socketCall, apiCall, tmpDir, freeTcpPort, startCli, runCli, waitFor, captureConsole } = require('./helpers');

const { NameDB, ApiCore, ApiServer, ControlServer } = lib;

function ok(r) {
	assert.equal(r.status, 200, r.text);
	assert.equal(r.body.status, 'ok');
	return r.body.data;
}

function bad(r, code, message) {
	assert.equal(r.status, code, r.text);
	assert.equal(r.body.status, 'error');
	assert.equal(r.body.code, code);
	if (message !== undefined) {
		assert.equal(r.body.message, message);
	}
}

describe('control socket', function() {

	let dir, sock, db, api, control, call;

	before(async function() {
		dir = tmpDir();
		sock = path.join(dir, 'control.sock');
		db = new NameDB();
		api = new ApiCore({ nameDB: db });
		control = new ControlServer({ api: api, path: sock });
		await once(control, 'ready');
		call = (urlPath, params, opts) => socketCall(sock, urlPath, params, opts);
	});

	after(async function() {
		await control.close();
		db.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	beforeEach(function() {
		db.flush();
		db.addDomain('example.com');
	});

	test('serves the API as GET with a query, POST with JSON and POST with a form', async function() {
		assert.deepEqual(ok(await call('/')), { 'package': 'tr-ddns', version: require('../package.json').version });
		ok(await call('/host', { host: 'g.example.com', a: [ '1.2.3.4', '5.6.7.8' ] }));
		ok(await call('/host', { host: 'p.example.com', a: [ '1.2.3.4' ], ttl: 60 }, { json: true }));
		ok(await call('/host', undefined, { method: 'POST', rawBody: 'host=f.example.com&txt=a&txt=b', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }));
		ok(await call('/record', { host: 'g.example.com', command: 'add', type: 'txt', value: 'hello' }, { json: true, method: 'PUT' }));
		let hosts = Object.fromEntries(ok(await call('/dump')).hosts.map((h) => [ h.lcname, h ]));
		assert.deepEqual(hosts['g.example.com'].data.a, [ '1.2.3.4', '5.6.7.8' ]);
		assert.deepEqual(hosts['g.example.com'].data.txt, [ 'hello' ]);
		assert.equal(typeof(hosts['p.example.com'].expires), 'number');
		assert.deepEqual(hosts['f.example.com'].data.txt, [ 'a', 'b' ]);
		ok(await call('/host', { host: 'g.example.com' }, { method: 'DELETE' }));
		assert.equal(db.stats().hosts, 2);
	});

	test('responses are JSON in the envelope of the API and are not cacheable', async function() {
		let r = await call('/');
		assert.match(r.headers.get('content-type'), /^application\/json/);
		assert.equal(r.headers.get('cache-control'), 'no-store');
		bad(await call('/host', { host: 'not valid' }), 400, 'Bad request (host)');
		bad(await call('/nope'), 404, 'Not found');
		bad(await call('/host/'), 404, 'Not found');
	});

	test('refuses what the API refuses on its TCP port', async function() {
		bad(await call('/', undefined, { method: 'PATCH' }), 405, 'Method Not Allowed');
		bad(await call('/host?host=h.example.com', {}, { json: true }), 400);
		bad(await call('/host', undefined, { method: 'GET', rawBody: 'x', headers: { 'Content-Length': '1' } }), 400);
		bad(await call('/host', undefined, { method: 'GET', rawBody: 'not framed as a body' }), 400, 'Bad Request');
		bad(await call('/host', undefined, { method: 'POST', rawBody: 'hello', headers: { 'Content-Type': 'text/plain' } }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: 'hello' }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: '{not json', headers: { 'Content-Type': 'application/json' } }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: '["x"]', headers: { 'Content-Type': 'application/json' } }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: 'null', headers: { 'Content-Type': 'application/json' } }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: '{}', headers: { 'Content-Type': 'application/json; charset=latin1' } }), 400);
		bad(await call('/host', undefined, { method: 'POST', rawBody: '{"host":"h.example.com","a":"1.2.3.4","x":{"__proto__":{}}}', headers: { 'Content-Type': 'application/json' } }), 400);
		bad(await call('/host?host=h.example.com&a=1.2.3.4&constructor=x'), 400);
		bad(await call('//host'), 400);
		bad(await call('/a/../host'), 400);
		bad(await call('/host', { host: 'h.example.com', txt: 'x'.repeat(70000) }, { json: true }), 413);
		assert.equal(db.stats().hosts, 0);
	});

	test('a JSON body with the charset given is accepted', async function() {
		ok(await call('/host', undefined, { method: 'POST', rawBody: '{"host":"h.example.com","a":"1.2.3.4"}', headers: { 'Content-Type': 'application/json; charset=UTF-8' } }));
	});

	test('needs no credentials, also when the TCP port does', async function() {
		let port = await freeTcpPort();
		let tcp = new ApiServer({ api: api, port: port, address: '127.0.0.1', basicAuth: Buffer.from('user:secret').toString('base64') });
		await once(tcp, 'ready');
		try {
			let base = 'http://127.0.0.1:' + port;
			assert.equal((await apiCall(base, '/dump')).status, 401);
			ok(await call('/dump'));
			ok(await call('/host', { host: 'shared.example.com', a: '1.2.3.4' }));
			let viaTcp = await apiCall(base, '/dump', undefined, { auth: 'user:secret' });
			assert.deepEqual(viaTcp.body.data.hosts.map((h) => h.name), [ 'shared.example.com' ], 'both serve the same database');
			let before = ok(await call('/stats'));
			await apiCall(base, '/');
			let after = ok(await call('/stats'));
			assert.equal(after.apiCalls - before.apiCalls, 2, 'calls through both are counted together');
			assert.equal(after.authFailures - before.authFailures, 1);
		} finally {
			await tcp.close();
		}
	});

	test('the socket file is private to its owner by default', function() {
		let st = fs.statSync(sock);
		assert.ok(st.isSocket());
		assert.equal(st.mode & 0o777, 0o600);
	});

});

describe('ControlServer', function() {

	let dir, db;

	beforeEach(function() {
		dir = tmpDir();
		db = new NameDB();
	});

	function cleanup() {
		db.close();
		fs.rmSync(dir, { recursive: true, force: true });
	}

	test('validates its options', function() {
		try {
			assert.throws(() => new ControlServer({ nameDB: db }), /socket path/);
			assert.throws(() => new ControlServer({ nameDB: db, path: '' }), /socket path/);
			assert.throws(() => new ControlServer({ path: path.join(dir, 's') }), /NameDB/);
			assert.throws(() => new ControlServer({ api: {}, path: path.join(dir, 's') }), /ApiCore/);
			assert.throws(() => new ControlServer({ nameDB: db, path: path.join(dir, 's'), mode: '999' }), /mode/);
			assert.throws(() => new ControlServer({ nameDB: db, path: path.join(dir, 's'), mode: -1 }), /mode/);
			assert.throws(() => new ControlServer({ nameDB: db, path: path.join(dir, 's'), maxBodySize: 'big' }), /body size/);
		} finally {
			cleanup();
		}
	});

	test('the permissions of the socket can be chosen', async function() {
		try {
			for (let [ mode, expected ] of [ [ '660', 0o660 ], [ 0o666, 0o666 ], [ '0640', 0o640 ] ]) {
				let s = path.join(dir, 'm.sock');
				let c = new ControlServer({ nameDB: db, path: s, mode: mode });
				await once(c, 'ready');
				assert.equal(fs.statSync(s).mode & 0o777, expected);
				await c.close();
			}
		} finally {
			cleanup();
		}
	});

	test('close removes the socket file', async function() {
		try {
			let s = path.join(dir, 'c.sock');
			let c = new ControlServer({ nameDB: db, path: s });
			await once(c, 'ready');
			await c.close();
			assert.equal(fs.existsSync(s), false);
			await c.close();
			let quick = new ControlServer({ nameDB: db, path: s });
			await quick.close();
			assert.equal(fs.existsSync(s), false, 'closing before it is up leaves nothing behind');
		} finally {
			cleanup();
		}
	});

	test('a socket file left behind by a dead process is replaced', async function() {
		try {
			let s = path.join(dir, 'stale.sock');
			let dead = net.createServer();
			await new Promise((r) => dead.listen(s, r));
			// Closing the handle without the usual cleanup leaves the file,
			// as a process that is killed does.
			fs.renameSync(s, s + '.keep');
			await new Promise((r) => dead.close(r));
			fs.renameSync(s + '.keep', s);
			assert.ok(fs.statSync(s).isSocket());
			let c = new ControlServer({ nameDB: db, path: s });
			await once(c, 'ready');
			assert.equal((await socketCall(s, '/')).status, 200);
			await c.close();
		} finally {
			cleanup();
		}
	});

	test('a socket that is in use is not taken over', async function() {
		try {
			let s = path.join(dir, 'busy.sock');
			let first = new ControlServer({ nameDB: db, path: s });
			await once(first, 'ready');
			let second = new ControlServer({ nameDB: db, path: s });
			let [ e ] = await once(second, 'error');
			assert.equal(e.code, 'EADDRINUSE');
			await second.close();
			assert.equal((await socketCall(s, '/')).status, 200, 'the first one still answers');
			await first.close();
		} finally {
			cleanup();
		}
	});

	test('a file that is not a socket is left alone', async function() {
		try {
			let s = path.join(dir, 'file');
			fs.writeFileSync(s, 'precious');
			let c = new ControlServer({ nameDB: db, path: s });
			let [ e ] = await once(c, 'error');
			assert.equal(e.code, 'EEXIST');
			assert.equal(fs.readFileSync(s, 'utf8'), 'precious');
			await c.close();
		} finally {
			cleanup();
		}
	});

	test('a directory that does not exist is an error', async function() {
		try {
			let c = new ControlServer({ nameDB: db, path: path.join(dir, 'missing', 'c.sock') });
			let [ e ] = await once(c, 'error');
			assert.ok([ 'ENOENT', 'EACCES' ].includes(e.code), e.code);
			await c.close();
		} finally {
			cleanup();
		}
	});

	test('a request body that stops arriving times out', { timeout: 15000 }, async function() {
		try {
			let s = path.join(dir, 'slow.sock');
			let c = new ControlServer({ nameDB: db, path: s });
			await once(c, 'ready');
			let response = await new Promise(function(resolve) {
				let sockConn = net.connect(s);
				let data = '';
				sockConn.on('data', (d) => { data += d; });
				sockConn.on('close', () => resolve(data));
				sockConn.on('error', () => resolve(data));
				sockConn.write('POST /host HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"host":');
			});
			assert.match(response, /^HTTP\/1\.1 408 /);
			await c.close();
		} finally {
			cleanup();
		}
	});

});

describe('--control-socket', function() {

	async function start(t, extra) {
		let dir = tmpDir();
		let cf = path.join(dir, 'config.json');
		let sock = path.join(dir, 'c.sock');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		let h = await startCli([ '-c', cf, '--control-socket=' + sock, '--config-write-interval=0' ].concat(extra ?? []), {});
		t.after(async function() {
			await h.stop('SIGKILL');
			fs.rmSync(dir, { recursive: true, force: true });
		});
		await waitFor(() => (h.exited || fs.existsSync(sock)));
		return { h, dir, cf, sock };
	}

	test('serves the API without any network port', async function(t) {
		let s = await start(t);
		assert.equal((await socketCall(s.sock, '/domain', { domain: 'example.com' })).status, 200);
		assert.equal((await socketCall(s.sock, '/host', { host: 'h.example.com', a: '1.2.3.4' })).status, 200);
		await waitFor(() => (JSON.parse(fs.readFileSync(s.cf, 'utf8')).hosts.length === 1));
		assert.equal(fs.statSync(s.sock).mode & 0o777, 0o600);
		assert.doesNotMatch(s.h.stderr, /Warning/);
	});

	test('the socket is removed when the program stops', async function(t) {
		let s = await start(t);
		await s.h.stop('SIGTERM');
		assert.equal(s.h.code, 0);
		assert.equal(fs.existsSync(s.sock), false);
	});

	test('--control-socket-mode sets the permissions', async function(t) {
		let s = await start(t, [ '--control-socket-mode=660' ]);
		assert.equal(fs.statSync(s.sock).mode & 0o777, 0o660);
		let r = await runCli([ '-c', s.cf, '--control-socket=' + s.sock + '2', '--control-socket-mode=rw' ]);
		assert.notEqual(r.code, 0);
	});

	test('a second program on the same socket does not start', async function(t) {
		let s = await start(t);
		let r = await runCli([ '-c', s.cf, '--control-socket=' + s.sock ]);
		assert.equal(r.code, 1);
		assert.match(r.stderr, /Unable to start control socket \(EADDRINUSE\)/);
		assert.equal((await socketCall(s.sock, '/')).status, 200);
	});

	test('the path can be given in the environment', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'config.json');
		let sock = path.join(dir, 'env.sock');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		let h = await startCli([ '-c', cf ], { env: { TR_DDNS_OPT_CONTROL_SOCKET: sock, TR_DDNS_OPT_CONTROL_SOCKET_MODE: '666' } });
		t.after(async function() {
			await h.stop('SIGKILL');
			fs.rmSync(dir, { recursive: true, force: true });
		});
		await waitFor(() => fs.existsSync(sock));
		assert.equal(fs.statSync(sock).mode & 0o777, 0o666);
	});

});
