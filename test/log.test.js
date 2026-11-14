'use strict';

const { test, describe, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { lib, captureConsole, tmpDir, runCli, startCli, freeTcpPort, apiCall, waitFor } = require('./helpers');

const { log } = lib;

async function captureStreams(fn) {
	let out = [], err = [];
	let saved = { log: console.log, error: console.error };
	console.log = function(...av) { out.push(av.join(' ')); };
	console.error = function(...av) { err.push(av.join(' ')); };
	try {
		await fn();
	} finally {
		Object.assign(console, saved);
	}
	return { out, err };
}

describe('log', function() {

	afterEach(function() {
		log.setLevel('info');
	});

	test('log() prints an informational message with a time stamp', async function() {
		let lines = await captureConsole(() => { log('hello', 'world'); });
		assert.equal(lines.length, 1);
		assert.match(lines[0], /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: hello world$/);
	});

	test('the level decides what is printed', async function() {
		let all = function() {
			log.error('e');
			log.warn('w');
			log.info('i');
			log('l');
			log.debug('d');
		};
		let seen = {};
		for (let level of [ 'none', 'error', 'warn', 'info', 'debug' ]) {
			log.setLevel(level);
			assert.equal(log.getLevel(), level);
			seen[level] = (await captureConsole(all)).map((l) => l.slice(-1)).join('');
		}
		assert.deepEqual(seen, { none: '', error: 'e', warn: 'ew', info: 'ewil', debug: 'ewild' });
	});

	test('errors and warnings go to the standard error', async function() {
		log.setLevel('debug');
		let r = await captureStreams(function() {
			log.error('e');
			log.warn('w');
			log.info('i');
			log.debug('d');
		});
		assert.deepEqual(r.err.map((l) => l.slice(-1)), [ 'e', 'w' ]);
		assert.deepEqual(r.out.map((l) => l.slice(-1)), [ 'i', 'd' ]);
	});

	test('the default level is info and an unknown level is refused', function() {
		assert.equal(log.getLevel(), 'info');
		assert.throws(() => log.setLevel('loud'), /Invalid log level/);
		assert.deepEqual(log.LEVELS, [ 'none', 'error', 'warn', 'info', 'debug' ]);
	});

	test('a component created with debug switches debug messages on', function() {
		let db = new lib.NameDB({ debug: true });
		db.close();
		assert.equal(log.getLevel(), 'debug');
	});

});

describe('--log-level', function() {

	async function run(t, args) {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, JSON.stringify({ domains: [ { name: 'example.com' }, { name: 'not valid' } ], hosts: [] }));
		let port = await freeTcpPort();
		let base = 'http://127.0.0.1:' + port;
		let h = await startCli([ '-c', cf, '--http-api', '--http-api-listen-address=127.0.0.1', '--http-api-listen-port=' + port, '--config-write-interval=0' ].concat(args),
							   { waitUrl: base + '/' });
		t.after(async function() {
			await h.stop('SIGKILL');
			fs.rmSync(dir, { recursive: true, force: true });
		});
		assert.equal((await apiCall(base, '/host', { host: 'h.example.com', a: '1.2.3.4' })).status, 200);
		await waitFor(() => (JSON.parse(fs.readFileSync(cf, 'utf8')).hosts.length === 1));
		await new Promise((r) => setTimeout(r, 100));
		await h.stop();
		return h;
	}

	test('info is the default: warnings and writes of the configuration', async function(t) {
		let h = await run(t, []);
		assert.match(h.stderr, /Ignored invalid domain entry \(not valid\)/);
		assert.match(h.stdout, /Config written/);
		assert.doesNotMatch(h.stdout, /EVENT/);
	});

	test('warn leaves out the informational messages', async function(t) {
		let h = await run(t, [ '--log-level=warn' ]);
		assert.match(h.stderr, /Ignored invalid domain entry/);
		assert.equal(h.stdout, '');
	});

	test('none prints nothing', async function(t) {
		let h = await run(t, [ '--log-level=none' ]);
		assert.equal(h.stdout + h.stderr, '');
	});

	test('debug is the same as --debug', async function(t) {
		let h = await run(t, [ '--log-level=debug' ]);
		assert.match(h.stdout, /EVENT: add\(h\.example\.com\)/);
		assert.match(h.stdout, /Stopping on SIGTERM/);
		let viaEnv = await run(t, []);
		assert.doesNotMatch(viaEnv.stdout, /EVENT/);
	});

	test('an unknown level is refused', async function() {
		let dir = tmpDir();
		let cf = path.join(dir, 'c.json');
		fs.writeFileSync(cf, '{"hosts":[],"domains":[]}');
		try {
			let r = await runCli([ '-c', cf, '--log-level=loud' ]);
			assert.notEqual(r.code, 0);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

});
