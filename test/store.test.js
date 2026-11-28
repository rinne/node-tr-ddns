'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');

const { lib, Packet, tmpDir, waitFor, full } = require('./helpers');

const { NameDB, ConfigStore } = lib;

function readJson(fn) {
	return JSON.parse(fs.readFileSync(fn, 'utf8'));
}

describe('ConfigStore', function() {

	let dir, file, db, store;

	beforeEach(function() {
		dir = tmpDir();
		file = path.join(dir, 'config.json');
		db = new NameDB();
		store = new ConfigStore({ file: file, nameDB: db, writeIntervalMs: 200 });
	});

	afterEach(function() {
		store.close();
		db.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	test('validates its options', function() {
		assert.throws(() => new ConfigStore({ nameDB: db }), /file name/);
		assert.throws(() => new ConfigStore({ file: file }), /NameDB/);
		assert.throws(() => new ConfigStore({ file: file, nameDB: db, writeIntervalMs: -1 }), /interval/);
	});

	test('init creates the file once', async function() {
		await store.init();
		assert.deepEqual(readJson(file), { hosts: [], domains: [] });
		await assert.rejects(store.init(), { code: 'EEXIST' });
	});

	test('load fails for a missing or malformed file', async function() {
		await assert.rejects(store.load(), { code: 'ENOENT' });
		for (let content of [ '', 'x', '[]', '{}', '{"hosts":[]}', '{"hosts":1,"domains":[]}', 'null' ]) {
			fs.writeFileSync(file, content);
			await assert.rejects(store.load(), { code: 'EMALFORMED' }, content);
		}
	});

	test('load fills the database and reports what it skipped', async function() {
		let now = Date.now();
		fs.writeFileSync(file, JSON.stringify({
			domains: [ { name: 'example.com' }, { name: 'bad domain' }, { name: 'example.com' }, 7 ],
			hosts: [ { name: 'ok.example.com', data: { a: [ '1.2.3.4' ], txt: 'old style' } },
					 { name: 'timed.example.com', data: { a: '1.2.3.4' }, expires: now + 60000 },
					 { name: 'expired.example.com', data: { a: '1.2.3.4' }, expires: now - 1 },
					 { name: 'garbage.example.com', data: { a: [ 'not an address' ] } },
					 { name: 'garbage2.example.com', data: { txt: [ 7 ] } },
					 { name: 'garbage3.example.com', data: { a: '1.2.3.4' }, expires: 'tomorrow' },
					 { name: 'nodata.example.com' },
					 { name: 'elsewhere.example.org', data: { a: '1.2.3.4' } },
					 { name: 'bad name', data: { a: '1.2.3.4' } },
					 'x' ]
		}));
		let warnings = await store.load();
		let d = db.dump();
		assert.deepEqual(d.domains.map((x) => x.name), [ 'example.com' ]);
		assert.deepEqual(d.hosts.map((x) => x.name).sort(), [ 'ok.example.com', 'timed.example.com' ]);
		assert.deepEqual(d.hosts.find((x) => (x.name === 'ok.example.com')).data, full({ a: [ '1.2.3.4' ], aaaa: [], txt: [ 'old style' ], mx: [] }));
		assert.ok(Math.abs(d.hosts.find((x) => (x.name === 'timed.example.com')).expires - (now + 60000)) < 2000);
		assert.equal(warnings.length, 10);
		for (let name of [ 'bad domain', 'example.com', 'garbage.example.com', 'garbage2.example.com', 'garbage3.example.com',
						   'nodata.example.com', 'elsewhere.example.org', 'bad name' ]) {
			assert.ok(warnings.some((w) => w.includes('(' + name + ')')), name);
		}
		assert.ok(! warnings.some((w) => w.includes('expired.example.com')), 'an expired host is dropped silently');
	});

	test('a serial from the file is continued', async function() {
		let ahead = (Math.floor(Date.now() / 15) % 4294967295) + 500000;
		fs.writeFileSync(file, JSON.stringify({ domains: [ { name: 'example.com', serial: ahead } ], hosts: [] }));
		await store.load();
		assert.equal(db.get('example.com', Packet.TYPE.SOA)[0].serial, ahead);
	});

	test('the settings of a domain are saved and loaded', async function() {
		db.addDomain('example.com', { ns: [ 'ns1.example.net', 'ns2.example.net' ], admin: 'hostmaster@example.com', ttl: 300, minimum: 120 });
		db.addDomain('plain.test');
		db.set('alias.example.com', { cname: 'www.example.com' });
		db.set('_sip._tcp.example.com', { srv: '10 5 5060 sip.example.com' });
		await store.write();
		let saved = readJson(file).domains;
		assert.deepEqual(Object.keys(saved.find((d) => (d.name === 'plain.test'))).sort(), [ 'expires', 'lcname', 'name', 'serial' ]);
		let other = new NameDB();
		let otherStore = new ConfigStore({ file: file, nameDB: other });
		try {
			assert.deepEqual(await otherStore.load(), []);
			let a = db.getDomain('example.com'), b = other.getDomain('example.com');
			a.serial = b.serial = 0;
			assert.deepEqual(a, b);
			assert.deepEqual(other.dump().hosts, db.dump().hosts);
		} finally {
			otherStore.close();
			other.close();
		}
	});

	test('a domain with unusable settings is served with the defaults', async function() {
		fs.writeFileSync(file, JSON.stringify({
			domains: [ { name: 'example.com', ns: [ 'not valid' ], ttl: 300 } ],
			hosts: [ { name: 'h.example.com', data: { a: [ '1.2.3.4' ] } } ]
		}));
		let warnings = await store.load();
		assert.equal(warnings.length, 1);
		assert.match(warnings[0], /Ignored invalid settings of domain entry \(example\.com\)/);
		assert.deepEqual(db.getDomain('example.com').ns, [ 'example.com' ]);
		assert.equal(db.getDomain('example.com').ttl, 60);
		assert.equal(db.stats().hosts, 1);
	});

	test('what is written can be loaded again', async function() {
		db.addDomain('example.com');
		db.set('h.example.com', { a: [ '1.2.3.4', '5.6.7.8' ], aaaa: '2001:db8::1', txt: 'hello', mx: 'mail.example.com' }, 3600000);
		await store.write();
		let other = new NameDB();
		let otherStore = new ConfigStore({ file: file, nameDB: other });
		try {
			assert.deepEqual(await otherStore.load(), []);
			let a = db.dump(), b = other.dump();
			assert.ok(Math.abs(a.hosts[0].expires - b.hosts[0].expires) < 2000);
			a.hosts[0].expires = b.hosts[0].expires = 0;
			a.domains[0].serial = b.domains[0].serial = 0;
			assert.deepEqual(a, b);
		} finally {
			otherStore.close();
			other.close();
		}
	});

	test('write replaces the file in one step and leaves nothing else behind', async function() {
		fs.writeFileSync(file, '{"hosts":[],"domains":[]}');
		let inode = fs.statSync(file).ino;
		db.addDomain('example.com');
		await store.write();
		assert.equal(readJson(file).domains.length, 1);
		assert.notEqual(fs.statSync(file).ino, inode, 'a new file took the place of the old one');
		assert.deepEqual(fs.readdirSync(dir), [ 'config.json' ]);
	});

	test('write keeps the permissions of the file', { skip: (process.platform === 'win32') }, async function() {
		fs.writeFileSync(file, '{"hosts":[],"domains":[]}', { mode: 0o600 });
		fs.chmodSync(file, 0o600);
		await store.write();
		assert.equal(fs.statSync(file).mode & 0o777, 0o600);
	});

	test('write follows a symbolic link', { skip: (process.platform === 'win32') }, async function() {
		let real = path.join(dir, 'real.json');
		fs.writeFileSync(real, '{"hosts":[],"domains":[]}');
		fs.symlinkSync(real, file);
		db.addDomain('example.com');
		await store.write();
		assert.ok(fs.lstatSync(file).isSymbolicLink());
		assert.equal(readJson(real).domains.length, 1);
	});

	test('a file that cannot be replaced (EBUSY) is written in place', async function() {
		fs.writeFileSync(file, '{"hosts":[],"domains":[],"padding":"' + 'x'.repeat(1000) + '"}');
		let inode = fs.statSync(file).ino;
		db.addDomain('example.com');
		let rename = fs.promises.rename;
		fs.promises.rename = async function() {
			let e = new Error('EBUSY: resource busy or locked, rename');
			e.code = 'EBUSY';
			throw e;
		};
		try {
			await store.write();
		} finally {
			fs.promises.rename = rename;
		}
		assert.equal(fs.statSync(file).ino, inode, 'the same file was written');
		assert.deepEqual(readJson(file), { hosts: [], domains: db.dump().domains });
		assert.deepEqual(fs.readdirSync(dir), [ 'config.json' ]);
	});

	test('a failed write leaves the old file intact', { skip: (process.platform === 'win32') || (process.getuid?.() === 0) }, async function() {
		fs.writeFileSync(file, '{"hosts":[],"domains":[]}');
		db.addDomain('example.com');
		fs.chmodSync(dir, 0o500);
		try {
			await assert.rejects(store.write());
		} finally {
			fs.chmodSync(dir, 0o700);
		}
		assert.deepEqual(readJson(file), { hosts: [], domains: [] });
		assert.deepEqual(fs.readdirSync(dir), [ 'config.json' ]);
	});

	test('changes are written, and changes in quick succession together', async function() {
		let writes = 0;
		store.on('write', () => writes++);
		store.watch();
		db.addDomain('example.com');
		await once(store, 'write');
		assert.equal(readJson(file).domains.length, 1, 'the first change is written at once');
		db.set('a.example.com', { a: '1.2.3.4' });
		db.set('b.example.com', { a: '1.2.3.4' });
		db.set('c.example.com', { a: '1.2.3.4' });
		db.remove('a.example.com');
		assert.equal(readJson(file).hosts.length, 0, 'not yet');
		await once(store, 'write');
		assert.deepEqual(readJson(file).hosts.map((h) => h.name).sort(), [ 'b.example.com', 'c.example.com' ]);
		assert.equal(writes, 2);
	});

	test('a write at startup does not delay the first change', async function() {
		let slow = new ConfigStore({ file: file, nameDB: db, writeIntervalMs: 60000 });
		try {
			await slow.write({ untimed: true });
			slow.watch();
			db.addDomain('example.com');
			await once(slow, 'write');
			assert.equal(readJson(file).domains.length, 1);
		} finally {
			slow.close();
		}
	});

	test('flush writes pending changes now', async function() {
		let slow = new ConfigStore({ file: file, nameDB: db, writeIntervalMs: 60000 });
		try {
			slow.watch();
			db.addDomain('example.com');
			await once(slow, 'write');
			db.set('h.example.com', { a: '1.2.3.4' });
			assert.equal(readJson(file).hosts.length, 0);
			await slow.flush();
			assert.equal(readJson(file).hosts.length, 1);
			await slow.flush();
		} finally {
			slow.close();
		}
	});

	test('a write that fails later is reported as an error event', async function() {
		store.watch();
		fs.rmSync(dir, { recursive: true, force: true });
		db.addDomain('example.com');
		let [ e ] = await once(store, 'error');
		assert.equal(e.code, 'ENOENT');
		fs.mkdirSync(dir, { recursive: true });
	});

	test('close stops following the database', async function() {
		store.watch();
		store.close();
		db.addDomain('example.com');
		await new Promise((r) => setTimeout(r, 300));
		assert.equal(fs.existsSync(file), false);
	});

});
