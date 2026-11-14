'use strict';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { once } = require('node:events');

const { ROOT, lib, tmpDir, runCli, startCli, waitFor } = require('./helpers');

const CTL = path.join(ROOT, 'bin', 'tr-ddns-ctl');

describe('tr-ddns-ctl', function() {

	let dir, sock, db, control;

	// Runs the command. The socket comes from the environment unless
	// the arguments name one.
	function ctl(args, env) {
		return runCli(args, { cli: CTL, env: Object.assign({ TR_DDNS_OPT_CONTROL_SOCKET: sock }, env) });
	}

	async function ok(args) {
		let r = await ctl(args);
		assert.equal(r.code, 0, args.join(' ') + ': ' + r.stderr);
		assert.equal(r.stderr, '');
		return r.stdout;
	}

	async function fails(args, code, message) {
		let r = await ctl(args);
		assert.equal(r.code, code, args.join(' ') + ': ' + r.stdout + r.stderr);
		if (message !== undefined) {
			assert.match(r.stderr, message);
		}
		return r;
	}

	function hostData(name) {
		let h = db.dump().hosts.find((x) => (x.lcname === name));
		return h ? Object.fromEntries(Object.entries(h.data).filter(([ , v ]) => (v.length > 0))) : undefined;
	}

	before(async function() {
		dir = tmpDir();
		sock = path.join(dir, 'control.sock');
		db = new lib.NameDB();
		control = new lib.ControlServer({ nameDB: db, path: sock });
		await once(control, 'ready');
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

	test('info names the server', async function() {
		assert.equal(await ok([ 'info' ]), 'tr-ddns ' + require('../package.json').version + '\n');
	});

	test('the socket can be given as an option', async function() {
		let r = await runCli([ '-s', sock, 'info' ], { cli: CTL });
		assert.equal(r.code, 0);
		r = await runCli([ '--socket=' + sock, 'info' ], { cli: CTL });
		assert.equal(r.code, 0);
	});

	describe('domains', function() {

		test('add, list, show and remove', async function() {
			assert.equal(await ok([ 'domain', 'add', 'Example.ORG', 'ns=ns1.example.org', 'ns=ns2.example.org', 'admin=hostmaster@example.org', 'ttl=300' ]), '');
			assert.equal(await ok([ 'domain', 'list' ]), 'Example.ORG\nexample.com\n');
			let shown = await ok([ 'domain', 'show', 'example.org.' ]);
			assert.match(shown, /^name Example\.ORG\nserial \d+\nns ns1\.example\.org\nns ns2\.example\.org\nadmin hostmaster\.example\.org\nttl 300\n$/);
			assert.equal(await ok([ 'domain', 'remove', 'example.org' ]), '');
			assert.equal(await ok([ 'domain', 'list' ]), 'example.com\n');
			assert.equal(await ok([ 'domain', 'remove', 'example.org' ]), '', 'removing what is not served is fine');
		});

		test('add fails for a served domain, ensure does not', async function() {
			await fails([ 'domain', 'add', 'example.com' ], 1, /^tr-ddns-ctl: Bad request \(unable to add domain\)\n$/);
			await ok([ 'domain', 'ensure', 'example.com' ]);
			await ok([ 'domain', 'ensure', 'example.org' ]);
			await ok([ 'domain', 'ensure', 'example.org' ]);
			assert.equal(db.stats().domains, 2);
			await fails([ 'domain', 'ensure', 'sub.example.com' ], 1, /unable to add domain/);
		});

		test('ensure applies the settings given and leaves the others', async function() {
			await ok([ 'domain', 'ensure', 'example.org', 'ttl=300', 'ns=ns.example.net' ]);
			await ok([ 'domain', 'ensure', 'example.org', 'ttl=120' ]);
			let d = db.getDomain('example.org');
			assert.deepEqual([ d.ttl, d.ns ], [ 120, [ 'ns.example.net' ] ]);
			await ok([ 'domain', 'ensure', 'example.org' ]);
			assert.equal(db.getDomain('example.org').ttl, 120);
		});

		test('set changes settings, and an empty value resets one', async function() {
			await ok([ 'domain', 'set', 'example.com', 'ttl=120', 'minimum=30' ]);
			await ok([ 'domain', 'set', 'example.com', 'ttl=' ]);
			let d = db.getDomain('example.com');
			assert.deepEqual([ d.ttl, d.minimum ], [ 60, 30 ]);
			await fails([ 'domain', 'set', 'example.org', 'ttl=5' ], 1, /unable to update domain/);
			await fails([ 'domain', 'set', 'example.com', 'ttl=soon' ], 1, /Bad request \(ttl\)/);
		});

		test('show fails for a domain that is not served', async function() {
			await fails([ 'domain', 'show', 'example.org' ], 1, /^tr-ddns-ctl: No such domain\n$/);
		});

	});

	describe('hosts', function() {

		test('set replaces, merge keeps', async function() {
			await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.10', 'a=192.0.2.11', 'txt=hello' ]);
			assert.deepEqual(hostData('www.example.com'), { a: [ '192.0.2.10', '192.0.2.11' ], txt: [ 'hello' ] });
			await ok([ 'host', 'merge', 'www.example.com', 'aaaa=2001:db8::1' ]);
			assert.deepEqual(Object.keys(hostData('www.example.com')).sort(), [ 'a', 'aaaa', 'txt' ]);
			await ok([ 'host', 'merge', 'www.example.com', 'txt=' ]);
			assert.deepEqual(Object.keys(hostData('www.example.com')).sort(), [ 'a', 'aaaa' ]);
			await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.12' ]);
			assert.deepEqual(hostData('www.example.com'), { a: [ '192.0.2.12' ] });
		});

		test('a value may contain an equal sign and spaces', async function() {
			await ok([ 'host', 'set', 'example.com', 'txt=v=spf1 mx -all', 'mx=10 mail.example.com', 'caa=0 issue letsencrypt.org' ]);
			assert.deepEqual(hostData('example.com'), { txt: [ 'v=spf1 mx -all' ], mx: [ '10 mail.example.com' ], caa: [ '0 issue letsencrypt.org' ] });
		});

		test('ttl gives the host a lifetime', async function() {
			await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.10', 'ttl=3600' ]);
			let expires = db.getHostExpires('www.example.com');
			assert.ok(Math.abs(expires - (Date.now() + 3600000)) < 10000);
			assert.match(await ok([ 'host', 'show', 'www.example.com' ]), /^a 192\.0\.2\.10\nexpires \d{4}-\d\d-\d\dT[\d:.]+Z\n$/);
		});

		test('list and show', async function() {
			db.addDomain('example.org');
			await ok([ 'host', 'set', 'b.example.com', 'a=192.0.2.2' ]);
			await ok([ 'host', 'set', 'A.example.com', 'a=192.0.2.1', 'txt=x' ]);
			await ok([ 'host', 'set', 'c.example.org', 'a=192.0.2.3' ]);
			assert.equal(await ok([ 'host', 'list' ]), 'A.example.com\nb.example.com\nc.example.org\n');
			assert.equal(await ok([ 'host', 'list', 'Example.ORG' ]), 'c.example.org\n');
			assert.equal(await ok([ 'host', 'show', 'a.example.com' ]), 'a 192.0.2.1\ntxt x\n');
			await fails([ 'host', 'show', 'nope.example.com' ], 1, /No such host/);
			await fails([ 'host', 'list', 'example.net' ], 1, /No such domain/);
		});

		test('remove fails for a host that is not there, unless told otherwise', async function() {
			await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.10' ]);
			await ok([ 'host', 'remove', 'www.example.com' ]);
			await fails([ 'host', 'remove', 'www.example.com' ], 1, /unable to remove host/);
			await ok([ '--if-exists', 'host', 'remove', 'www.example.com' ]);
			await fails([ '--if-exists', 'host', 'remove', 'www.example.net' ], 1, /unable to remove host/);
		});

		test('set and merge need a record, so that a slip does not remove the host', async function() {
			await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.10' ]);
			await fails([ 'host', 'set', 'www.example.com' ], 2);
			await fails([ 'host', 'set', 'www.example.com', 'ttl=60' ], 2, /needs at least one/);
			await fails([ 'host', 'merge', 'www.example.com', 'ttl=60' ], 2);
			assert.deepEqual(hostData('www.example.com'), { a: [ '192.0.2.10' ] });
		});

		test('the server decides what is a valid value', async function() {
			await fails([ 'host', 'set', 'www.example.com', 'a=bogus' ], 1, /^tr-ddns-ctl: Bad request \(a\)\n$/);
			await fails([ 'host', 'set', 'www.example.net', 'a=192.0.2.1' ], 1, /unable to add\/update host/);
		});

	});

	describe('records', function() {

		test('add, remove, set and clear', async function() {
			await ok([ 'record', 'add', 'www.example.com', 'a', '192.0.2.10' ]);
			await ok([ 'record', 'add', 'www.example.com', 'a', '192.0.2.11' ]);
			await ok([ 'record', 'add', 'www.example.com', 'txt', 'one two' ]);
			await ok([ 'record', 'remove', 'www.example.com', 'a', '192.0.2.10' ]);
			assert.deepEqual(hostData('www.example.com'), { a: [ '192.0.2.11' ], txt: [ 'one two' ] });
			await ok([ 'record', 'set', 'www.example.com', 'txt', 'three' ]);
			await ok([ 'record', 'clear', 'www.example.com', 'a' ]);
			assert.deepEqual(hostData('www.example.com'), { txt: [ 'three' ] });
			await fails([ 'record', 'add', 'www.example.com', 'bogus', 'x' ], 1, /Bad request \(type\)/);
		});

	});

	test('dump and stats print JSON', async function() {
		await ok([ 'host', 'set', 'www.example.com', 'a=192.0.2.10' ]);
		let dump = JSON.parse(await ok([ 'dump' ]));
		assert.deepEqual(dump.hosts.map((h) => h.name), [ 'www.example.com' ]);
		assert.deepEqual(dump.domains.map((d) => d.name), [ 'example.com' ]);
		let stats = JSON.parse(await ok([ 'stats' ]));
		assert.equal(stats.hosts, 1);
		assert.ok(stats.apiCalls > 0);
	});

	test('flush needs --yes', async function() {
		await fails([ 'flush' ], 2, /--yes/);
		assert.equal(db.stats().domains, 1);
		await ok([ '--yes', 'flush' ]);
		assert.equal(db.stats().domains, 0);
	});

	test('--json prints the response of the server', async function() {
		assert.deepEqual(JSON.parse(await ok([ '--json', 'domain', 'ensure', 'example.org' ])), { status: 'ok', code: 200 });
		assert.deepEqual(JSON.parse(await ok([ '--json', 'info' ])).data['package'], 'tr-ddns');
		assert.equal(JSON.parse(await ok([ '--json', 'host', 'list' ])).data.hosts.length, 0);
		let r = await fails([ '--json', 'domain', 'add', 'example.com' ], 1);
		assert.deepEqual(JSON.parse(r.stdout), { status: 'error', code: 400, message: 'Bad request (unable to add domain)' });
	});

	test('an invalid command line sends nothing and exits with 2', async function() {
		let calls = db.stats();
		for (let args of [ [], [ 'bogus' ], [ 'domain' ], [ 'domain', 'bogus' ], [ 'domain', 'add' ], [ 'domain', 'add', 'example.org', 'colour=blue' ],
						   [ 'domain', 'add', 'example.org', 'ttl' ], [ 'domain', 'add', 'example.org', '=5' ], [ 'domain', 'set', 'example.com' ],
						   [ 'domain', 'show' ], [ 'domain', 'list', 'x' ], [ 'domain', 'remove' ],
						   [ 'host' ], [ 'host', 'bogus' ], [ 'host', 'set', 'www.example.com', 'colour=blue' ], [ 'host', 'show' ], [ 'host', 'remove' ],
						   [ 'host', 'list', 'a', 'b' ], [ 'record' ], [ 'record', 'add', 'www.example.com', 'a' ], [ 'record', 'clear', 'www.example.com' ],
						   [ 'record', 'bogus', 'x', 'y', 'z' ], [ 'info', 'x' ], [ 'dump', 'x' ], [ 'stats', 'x' ], [ 'wait', 'x' ], [ 'flush', 'x' ] ]) {
			await fails(args, 2);
		}
		assert.deepEqual(db.stats(), calls);
		assert.equal(db.dump().hosts.length, 0);
		let r = await runCli([ 'info' ], { cli: CTL });
		assert.equal(r.code, 2);
		assert.match(r.stderr, /No control socket given/);
		r = await ctl([ '--timeout=0', 'info' ]);
		assert.notEqual(r.code, 0);
		r = await ctl([ '--no-such-option', 'info' ]);
		assert.notEqual(r.code, 0);
	});

	test('--help lists the commands and exits with 0', async function() {
		let r = await ctl([ '--help' ]);
		assert.equal(r.code, 0);
		for (let word of [ 'wait', 'domain ensure', 'host merge', 'record clear', 'flush', 'Exit status' ]) {
			assert.ok(r.stdout.includes(word), word);
		}
	});

	describe('when the server cannot be reached', function() {

		test('exits with 3 when there is no socket', async function() {
			let r = await runCli([ '-s', path.join(dir, 'nothing.sock'), 'info' ], { cli: CTL });
			assert.equal(r.code, 3);
			assert.match(r.stderr, /^tr-ddns-ctl: No answer from the server \(ENOENT\)\n$/);
		});

		test('exits with 3 when nobody listens on the socket', async function() {
			let stale = path.join(dir, 'stale.sock');
			let srv = require('node:net').createServer();
			await new Promise((r) => srv.listen(stale, r));
			fs.renameSync(stale, stale + '.keep');
			await new Promise((r) => srv.close(r));
			fs.renameSync(stale + '.keep', stale);
			let r = await runCli([ '-s', stale, 'info' ], { cli: CTL });
			assert.equal(r.code, 3);
			assert.match(r.stderr, /ECONNREFUSED/);
		});

		test('exits with 3 when the server does not answer in time', async function() {
			let silent = path.join(dir, 'silent.sock');
			let srv = http.createServer(function() { /* never answers */ });
			await new Promise((r) => srv.listen(silent, r));
			try {
				let t0 = Date.now();
				let r = await runCli([ '-s', silent, '--timeout=1', 'info' ], { cli: CTL });
				assert.equal(r.code, 3);
				assert.match(r.stderr, /did not answer in time/);
				assert.ok((Date.now() - t0) < 5000);
			} finally {
				srv.closeAllConnections();
				await new Promise((r) => srv.close(r));
			}
		});

		test('exits with 3 when something else answers on the socket', async function() {
			let other = path.join(dir, 'other.sock');
			let srv = http.createServer(function(req, res) { res.end('hello'); });
			await new Promise((r) => srv.listen(other, r));
			try {
				let r = await runCli([ '-s', other, 'info' ], { cli: CTL });
				assert.equal(r.code, 3);
				assert.match(r.stderr, /not tr-ddns/);
			} finally {
				srv.closeAllConnections();
				await new Promise((r) => srv.close(r));
			}
		});

	});

	describe('wait', function() {

		test('returns at once when the server is up', async function() {
			assert.equal(await ok([ 'wait' ]), '');
		});

		test('gives up with 3 when the time is up', async function() {
			let t0 = Date.now();
			let r = await runCli([ '-s', path.join(dir, 'never.sock'), '--timeout=1', 'wait' ], { cli: CTL });
			assert.equal(r.code, 3);
			assert.ok(((Date.now() - t0) >= 900) && ((Date.now() - t0) < 5000));
		});

		test('returns when a server that is still starting comes up', async function(t) {
			let late = path.join(dir, 'late.sock');
			let waiting = runCli([ '-s', late, '--timeout=20', 'wait' ], { cli: CTL });
			await new Promise((r) => setTimeout(r, 500));
			let other = new lib.NameDB();
			let srv = new lib.ControlServer({ nameDB: other, path: late });
			t.after(async function() {
				await srv.close();
				other.close();
			});
			let r = await waiting;
			assert.equal(r.code, 0, r.stderr);
		});

	});

});

describe('tr-ddns-ctl with the real server', function() {

	test('a startup script can wait for the server and set it up, again and again', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'config.json');
		let sock = path.join(dir, 'c.sock');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		let env = { TR_DDNS_OPT_CONTROL_SOCKET: sock };
		t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
		let script = async function() {
			for (let args of [ [ '--timeout=20', 'wait' ],
							   [ 'domain', 'ensure', 'dyn.example.com', 'ns=ddns.example.com' ],
							   [ 'host', 'set', 'www.dyn.example.com', 'a=203.0.113.5' ] ]) {
				let r = await runCli(args, { cli: CTL, env: env });
				assert.equal(r.code, 0, args.join(' ') + ': ' + r.stderr);
			}
		};
		for (let round = 0; round < 2; round++) {
			let h = await startCli([ '-c', cf, '--config-write-interval=0' ], { env: env });
			try {
				await script();
				await waitFor(() => (JSON.parse(fs.readFileSync(cf, 'utf8')).hosts.length === 1));
			} finally {
				await h.stop();
			}
			assert.equal(h.code, 0);
		}
		let saved = JSON.parse(fs.readFileSync(cf, 'utf8'));
		assert.deepEqual(saved.domains.map((d) => [ d.name, d.ns ]), [ [ 'dyn.example.com', [ 'ddns.example.com' ] ] ]);
	});

});
