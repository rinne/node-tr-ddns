'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { TYPE, runCli, startCli, tmpDir, freePort, freeTcpPort, apiCall, dnsQuery, waitFor } = require('./helpers');

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

	test('a missing configuration file is reported as missing', { todo: 'Phase 1 item 12' }, async function() {
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
			hosts: [ { name: 'h.example.com', data: { a: [ '1.2.3.4', '5.6.7.8' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [] } } ]
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
		assert.deepEqual(d.hosts[0].data, { a: [ '1.2.3.4' ], aaaa: [ '2001:db8:0:0:0:0:0:1' ], txt: [ 'hello' ], mx: [] });
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

	test('stops on SIGTERM', async function(t) {
		let s = await startServer(t, { hosts: [], domains: [] });
		await s.h.stop('SIGTERM');
		assert.equal(s.h.exited, true);
	});

});
