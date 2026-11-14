'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { TYPE, LAUNCHER, startOfRatePeriod, runCli, startCli, tmpDir, freePort, freeTcpPort, apiCall, dnsQuery, waitFor, full } = require('./helpers');

function readJson(fn) {
	return JSON.parse(fs.readFileSync(fn, 'utf8'));
}

// Starts the server with the DNS and API listeners on loopback ports.
async function startServer(t, config, extraArgs, env, waitInit) {
	let dir = tmpDir();
	let cf = path.join(dir, 'config.json');
	if (config !== undefined) {
		fs.writeFileSync(cf, (typeof(config) === 'string') ? config : JSON.stringify(config));
	}
	let dnsPort = await freePort();
	let apiPort = await freeTcpPort();
	let base = 'http://127.0.0.1:' + apiPort;
	let args = [ '-c', cf,
				 '--udp', '--udp-listen-address=127.0.0.1', '--udp-listen-port=' + dnsPort,
				 '--tcp', '--tcp-listen-address=127.0.0.1', '--tcp-listen-port=' + dnsPort,
				 '--http-api', '--http-api-listen-address=127.0.0.1', '--http-api-listen-port=' + apiPort ].concat(extraArgs ?? []);
	let h = await startCli(args, { env: env, waitUrl: base + '/', waitInit: waitInit });
	t.after(async function() {
		await h.stop('SIGKILL');
		fs.rmSync(dir, { recursive: true, force: true });
	});
	return { h, dir, cf, dnsPort, apiPort, base };
}

describe('command line', function() {

	test('--help prints the options and exits with 0', async function() {
		let r = await runCli([ '--help' ]);
		assert.equal(r.code, 0);
		for (let o of [ '--debug', '--config-file', '--init-config-file', '--udp', '--udp-listen-address', '--udp-listen-port',
						'--tcp', '--tcp-listen-address', '--tcp-listen-port', '--http-api', '--http-api-user', '--http-api-password',
						'--http-api-listen-address', '--http-api-listen-port', '--help' ]) {
			assert.ok((r.stdout + r.stderr).includes(o), o);
		}
	});

	test('the launcher at the old path runs the same program', async function() {
		let r = await runCli([ '--help' ], { cli: LAUNCHER });
		let ref = await runCli([ '--help' ]);
		assert.equal(r.code, 0);
		assert.equal(r.stdout, ref.stdout);
		assert.match(r.stdout, /tr-ddns \[<opt> \.\.\.\]/);
	});

	test('the configuration file option is required', async function() {
		let r = await runCli([]);
		assert.notEqual(r.code, 0);
	});

	test('invalid option values are refused', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		try {
			for (let bad of [ [ '--udp-listen-port=0' ], [ '--udp-listen-port=65536' ], [ '--tcp-listen-port=x' ], [ '--udp-listen-address=nope' ],
							  [ '--http-api-listen-address=bogus' ], [ '--http-api-user=u' ], [ '--http-api-password=p' ], [ '--no-such-option' ] ]) {
				let r = await runCli([ '-c', cf ].concat(bad));
				assert.notEqual(r.code, 0, bad.join(' '));
			}
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('--init-config-file creates an empty configuration once', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		try {
			let r = await runCli([ '-c', cf, '--init-config-file' ]);
			assert.equal(r.code, 0, r.stderr);
			assert.deepEqual(readJson(cf), { hosts: [], domains: [] });
			r = await runCli([ '-c', cf, '--init-config-file' ]);
			assert.equal(r.code, 1);
			assert.match(r.stderr, /EEXIST/);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('a missing or malformed configuration file stops the program', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		try {
			let r = await runCli([ '-c', cf ]);
			assert.equal(r.code, 1);
			for (let content of [ '', 'not json', '[]', '{"hosts":[]}', '{"hosts":{},"domains":[]}' ]) {
				fs.writeFileSync(cf, content);
				r = await runCli([ '-c', cf ]);
				assert.equal(r.code, 1, content);
				assert.match(r.stderr, /Malformatted configuration/);
			}
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('a missing configuration file is reported as missing', async function() {
		let dir = tmpDir();
		try {
			let r = await runCli([ '-c', path.join(dir, 'c.json') ]);
			assert.equal(r.code, 1);
			assert.match(r.stderr, /not found|does not exist|ENOENT/i);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('exits without listeners when none is enabled', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		try {
			let h = await startCli([ '-c', cf ], {});
			await new Promise((r) => setTimeout(r, 300));
			assert.equal(h.exited, false, 'keeps running, as before');
			await h.stop('SIGKILL');
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

});

describe('server started from the command line', function() {

	test('serves DNS and the API from a configuration file', async function(t) {
		let s = await startServer(t, {
			domains: [ { name: 'example.com' } ],
			hosts: [ { name: 'h.example.com', data: full({ a: [ '1.2.3.4', '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [] }) } ]
		});
		let r = await dnsQuery(s.dnsPort, 'h.example.com', TYPE.A);
		assert.deepEqual(r.answers.map((a) => a.address).sort(), [ '1.2.3.4', '5.6.7.8' ]);
		r = await dnsQuery(s.dnsPort, 'h.example.com', TYPE.TXT, { tcp: true });
		assert.deepEqual(r.answers.map((a) => a.data), [ 'hello' ]);
		let d = await apiCall(s.base, '/dump');
		assert.equal(d.body.data.hosts.length, 1);
	});

	test('loads a configuration written before multi value records', async function(t) {
		let s = await startServer(t, {
			domains: [ { name: 'example.com', lcname: 'example.com', serial: 5, expires: null } ],
			hosts: [ { name: 'old.example.com', lcname: 'old.example.com', domain: 'example.com', data: { a: '1.2.3.4', aaaa: '2001:db8::1', txt: 'hello' }, expires: null } ]
		});
		let d = (await apiCall(s.base, '/dump')).body.data;
		assert.deepEqual(d.hosts[0].data, full({ a: [ '1.2.3.4' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [] }));
		assert.deepEqual(readJson(s.cf).hosts[0].data, d.hosts[0].data, 'the file is rewritten in the current format at startup');
	});

	test('skips expired hosts and unusable entries, keeps the rest', async function(t) {
		let now = Date.now();
		let s = await startServer(t, {
			domains: [ { name: 'example.com' }, { name: 'not valid' }, { name: 'sub.example.com' }, {}, null ],
			hosts: [ { name: 'gone.example.com', data: { a: [ '1.2.3.4' ] }, expires: now - 1000 },
					 { name: 'stays.example.com', data: { a: [ '1.2.3.4' ] }, expires: now + 3600000 },
					 { name: 'forever.example.com', data: { a: [ '1.2.3.4' ] }, expires: null },
					 { name: 'outside.example.org', data: { a: [ '1.2.3.4' ] } },
					 { name: 'not valid', data: { a: [ '1.2.3.4' ] } },
					 { name: 'nodata.example.com' },
					 {}, null ]
		});
		let d = (await apiCall(s.base, '/dump')).body.data;
		assert.deepEqual(d.domains.map((x) => x.name), [ 'example.com' ]);
		assert.deepEqual(d.hosts.map((x) => x.name).sort(), [ 'forever.example.com', 'stays.example.com' ]);
		let stays = d.hosts.find((x) => (x.name === 'stays.example.com'));
		assert.ok(Math.abs(stays.expires - (now + 3600000)) < 5000);
	});

	test('writes changes to the configuration file', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] });
		assert.equal((await apiCall(s.base, '/domain', { domain: 'example.com' })).status, 200);
		await waitFor(() => (readJson(s.cf).domains.length === 1));
		assert.equal(readJson(s.cf).domains[0].name, 'example.com');
	});

	test('options can be given in the environment', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[{"name":"example.com"}]}');
		let dnsPort = await freePort();
		let apiPort = await freeTcpPort();
		let base = 'http://127.0.0.1:' + apiPort;
		let h = await startCli([ '-c', cf ], {
			env: { TR_DDNS_OPT_UDP: 'true', TR_DDNS_OPT_UDP_LISTEN_ADDRESS: '127.0.0.1', TR_DDNS_OPT_UDP_LISTEN_PORT: String(dnsPort),
				   TR_DDNS_OPT_TCP: 'true', TR_DDNS_OPT_TCP_LISTEN_ADDRESS: '127.0.0.1', TR_DDNS_OPT_TCP_LISTEN_PORT: String(dnsPort),
				   TR_DDNS_OPT_HTTP_API: 'true', TR_DDNS_OPT_HTTP_API_LISTEN_ADDRESS: '127.0.0.1', TR_DDNS_OPT_HTTP_API_LISTEN_PORT: String(apiPort),
				   TR_DDNS_OPT_HTTP_API_USER: 'user', TR_DDNS_OPT_HTTP_API_PASSWORD: 'secret' },
			waitUrl: base + '/'
		});
		t.after(async function() {
			await h.stop('SIGKILL');
			fs.rmSync(dir, { recursive: true, force: true });
		});
		assert.equal((await apiCall(base, '/')).status, 401);
		assert.equal((await apiCall(base, '/', undefined, { auth: 'user:secret' })).status, 200);
		assert.equal((await dnsQuery(dnsPort, 'example.com', TYPE.SOA)).answers.length, 1);
		assert.equal((await dnsQuery(dnsPort, 'example.com', TYPE.SOA, { tcp: true })).answers.length, 1);
	});

	test('the API can be protected with a user name and a password', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] }, [ '--http-api-user=user', '--http-api-password=secret' ]);
		assert.equal((await apiCall(s.base, '/')).status, 401);
		assert.equal((await apiCall(s.base, '/', undefined, { auth: 'user:secret' })).status, 200);
	});

	test('--debug logs events', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] }, [ '--debug' ]);
		await apiCall(s.base, '/domain', { domain: 'example.com' });
		await waitFor(() => /EVENT: add/.test(s.h.stdout));
	});

	test('exits when a DNS listener cannot be started', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		let port = await freePort();
		let blocker = require('node:dgram').createSocket('udp4');
		await new Promise((r) => blocker.bind(port, '127.0.0.1', r));
		t.after(function() {
			blocker.close();
			fs.rmSync(dir, { recursive: true, force: true });
		});
		let r = await runCli([ '-c', cf, '--udp', '--udp-listen-address=127.0.0.1', '--udp-listen-port=' + port ]);
		assert.equal(r.code, 1);
		assert.match(r.stderr, /Unable to start DNS server \(EADDRINUSE\)/);
	});

	test('exits when the HTTP listener cannot be started', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		let blocker = require('node:net').createServer();
		await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
		t.after(function() {
			blocker.close();
			fs.rmSync(dir, { recursive: true, force: true });
		});
		let r = await runCli([ '-c', cf, '--http-api', '--http-api-listen-address=127.0.0.1', '--http-api-listen-port=' + blocker.address().port ]);
		assert.equal(r.code, 1);
		assert.match(r.stderr, /Unable to start HTTP server \(EADDRINUSE\)/);
	});

	for (let signal of [ 'SIGTERM', 'SIGINT' ]) {
		test('on ' + signal + ' writes pending changes and exits with 0', async function(t) {
			let s = await startServer(t, { hosts: [], domains: [] }, [ '--config-write-interval=3600' ]);
			assert.equal((await apiCall(s.base, '/domain', { domain: 'example.com' })).status, 200);
			await waitFor(() => (readJson(s.cf).domains.length === 1));
			assert.equal((await apiCall(s.base, '/host', { host: 'h.example.com', a: '1.2.3.4' })).status, 200);
			await new Promise((r) => setTimeout(r, 100));
			assert.equal(readJson(s.cf).hosts.length, 0, 'the second change waits for the write interval');
			await s.h.stop(signal);
			assert.equal(s.h.code, 0);
			assert.equal(s.h.signal, null);
			assert.equal(readJson(s.cf).hosts.length, 1);
			assert.deepEqual(fs.readdirSync(s.dir), [ 'config.json' ]);
		});
	}

	test('the write interval can be set to zero', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] }, [ '--config-write-interval=0' ]);
		for (let i = 0; i < 3; i++) {
			assert.equal((await apiCall(s.base, '/domain', { domain: 'example' + i + '.com' })).status, 200);
			await waitFor(() => (readJson(s.cf).domains.length === (i + 1)));
		}
	});

	test('the password can be read from a file', async function(t) {
		let dir = tmpDir();
		t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
		let pf = path.join(dir, 'password');
		fs.writeFileSync(pf, 'secret\n');
		let s = await startServer(t, { hosts: [], domains: [] }, [ '--http-api-user=user', '--http-api-password-file=' + pf ]);
		assert.equal((await apiCall(s.base, '/')).status, 401);
		assert.equal((await apiCall(s.base, '/', undefined, { auth: 'user:secret' })).status, 200);
		assert.equal((await apiCall(s.base, '/', undefined, { auth: 'user:secret\n' })).status, 401);
	});

	test('a password file that cannot be used stops the program', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		fs.writeFileSync(path.join(dir, 'empty'), '');
		fs.writeFileSync(path.join(dir, 'pw'), 'secret');
		try {
			let r = await runCli([ '-c', cf, '--http-api-user=u', '--http-api-password-file=' + path.join(dir, 'missing') ]);
			assert.equal(r.code, 1);
			assert.match(r.stderr, /password file \(ENOENT\)/);
			r = await runCli([ '-c', cf, '--http-api-user=u', '--http-api-password-file=' + path.join(dir, 'empty') ]);
			assert.equal(r.code, 1);
			r = await runCli([ '-c', cf, '--http-api-password-file=' + path.join(dir, 'pw') ]);
			assert.equal(r.code, 1);
			r = await runCli([ '-c', cf, '--http-api-user=u', '--http-api-password=x', '--http-api-password-file=' + path.join(dir, 'pw') ]);
			assert.notEqual(r.code, 0);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('warns when the API is reachable from other hosts without authentication', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
		let port = await freeTcpPort();
		let open = await startCli([ '-c', cf, '--http-api', '--http-api-listen-port=' + port ], { waitUrl: 'http://127.0.0.1:' + port + '/' });
		await open.stop();
		assert.match(open.stderr, /Warning: HTTP API listens on 0\.0\.0\.0 without authentication/);
		let secured = await startCli([ '-c', cf, '--http-api', '--http-api-listen-port=' + port, '--http-api-user=u', '--http-api-password=p' ],
									 { waitUrl: 'http://127.0.0.1:' + port + '/' });
		await secured.stop();
		assert.doesNotMatch(secured.stderr, /Warning/);
		let local = await startServer(t, { hosts: [], domains: [] });
		await local.h.stop();
		assert.doesNotMatch(local.h.stderr, /Warning/);
	});

	test('--dns-refuse-out-of-zone answers REFUSED outside the served domains', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [ { name: 'example.com' } ] }, [ '--dns-refuse-out-of-zone' ]);
		let r = await dnsQuery(s.dnsPort, 'example.org', TYPE.A);
		assert.equal(r.header.rcode, 5);
		let plain = await startServer(t, { hosts: [], domains: [ { name: 'example.com' } ] });
		assert.equal(await dnsQuery(plain.dnsPort, 'example.org', TYPE.A, { timeoutMs: 150 }), null);
	});

	test('the listen address options take a list', async function(t) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[{"name":"example.com"}]}');
		t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
		let hasIpv6 = await new Promise(function(resolve) {
			let sock = require('node:dgram').createSocket('udp6');
			sock.once('error', function() { resolve(false); });
			sock.bind(0, '::1', function() { sock.close(function() { resolve(true); }); });
		});
		let addresses = hasIpv6 ? [ '127.0.0.1', '::1' ] : [ '127.0.0.1' ];
		let dnsPort = await freePort();
		let apiPort = await freeTcpPort();
		let h = await startCli([ '-c', cf, '--udp', '--udp-listen-address=' + addresses.join(','), '--udp-listen-port=' + dnsPort,
								 '--tcp', '--tcp-listen-address=' + addresses.join(', '), '--tcp-listen-port=' + dnsPort,
								 '--http-api', '--http-api-listen-address=127.0.0.1', '--http-api-listen-port=' + apiPort ],
							   { waitUrl: 'http://127.0.0.1:' + apiPort + '/' });
		t.after(() => h.stop('SIGKILL'));
		for (let address of addresses) {
			for (let tcp of [ false, true ]) {
				let r = await dnsQuery(dnsPort, 'example.com', TYPE.SOA, { address, tcp });
				assert.equal(r.answers.length, 1, address);
			}
		}
		let r = await runCli([ '-c', cf, '--udp', '--udp-listen-address=127.0.0.1,nope' ]);
		assert.notEqual(r.code, 0);
	});

	test('the settings of a domain survive a restart', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] }, [ '--config-write-interval=0' ]);
		assert.equal((await apiCall(s.base, '/domain', { domain: 'example.com', ns: 'ns1.example.net', ttl: '300' })).status, 200);
		assert.equal((await apiCall(s.base, '/host', { host: 'alias.example.com', cname: 'www.example.com' })).status, 200);
		await s.h.stop();
		assert.equal(s.h.code, 0);
		let again = await startServer(t, readJson(s.cf));
		let r = await dnsQuery(again.dnsPort, 'example.com', TYPE.SOA);
		assert.equal(r.answers[0].primary, 'ns1.example.net');
		assert.equal(r.answers[0].ttl, 300);
		r = await dnsQuery(again.dnsPort, 'alias.example.com', TYPE.CNAME);
		assert.equal(r.answers[0].domain, 'www.example.com');
	});

	test('--dns-rate-limit limits the queries of one source', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [ { name: 'example.com' } ] }, [ '--dns-rate-limit=3' ]);
		await startOfRatePeriod((ms) => dnsQuery(s.dnsPort, 'example.com', TYPE.SOA, { timeoutMs: ms }));
		// One query of this second has been answered already.
		let answered = 0;
		for (let i = 0; i < 7; i++) {
			if ((await dnsQuery(s.dnsPort, 'example.com', TYPE.SOA, { timeoutMs: 40 })) !== null) {
				answered++;
			}
		}
		assert.equal(answered, 2);
		let d = (await apiCall(s.base, '/stats')).body.data;
		assert.ok(d.dns.dropped.rateLimited >= 5);
	});

	test('entries with unusable values in the configuration file are skipped with a warning', async function(t) {
		let s = await startServer(t, {
			domains: [ { name: 'example.com' } ],
			hosts: [ { name: 'good.example.com', data: { a: [ '1.2.3.4' ] } },
					 { name: 'bad.example.com', data: { a: [ 'not an address' ] } } ]
		});
		let d = (await apiCall(s.base, '/dump')).body.data;
		assert.deepEqual(d.hosts.map((h) => h.name), [ 'good.example.com' ]);
		assert.match(s.h.stderr, /Ignored invalid host entry \(bad\.example\.com\)/);
	});

});
