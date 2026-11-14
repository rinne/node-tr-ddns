'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT } = require('./helpers');

const pkg = require('../package.json');

// Everything that goes into the npm package. A file that is not on
// this list must not be published, and a file on this list must be.
const PUBLISHED = [
	'LICENSE',
	'MIT-RINNE',
	'README.md',
	'bin/tr-ddns',
	'lib/apiserver.js',
	'lib/index.js',
	'lib/log.js',
	'lib/namedb.js',
	'lib/nameserver.js',
	'lib/nullish.js',
	'lib/ts.js',
	'package.json',
	'tr-ddns'
];

describe('npm package', function() {

	test('contains exactly the intended files', function() {
		let out = execFileSync('npm', [ 'pack', '--dry-run', '--json', '--ignore-scripts' ], { cwd: ROOT, encoding: 'utf8', stdio: [ 'ignore', 'pipe', 'ignore' ] });
		let files = JSON.parse(out)[0].files.map((f) => f.path).sort();
		assert.deepEqual(files, PUBLISHED.slice().sort());
	});

	test('declares an allowlist of files', function() {
		assert.ok(Array.isArray(pkg.files) && (pkg.files.length > 0));
		for (let f of pkg.files) {
			assert.ok(fs.existsSync(path.join(ROOT, f)), f);
		}
	});

	test('the main entry exports the library', function() {
		let m = require(ROOT);
		assert.deepEqual(Object.keys(m).sort(), [ 'ApiServer', 'NameDB', 'NameServer', 'log', 'nullish', 'ts' ]);
		assert.equal(typeof(m.NameDB), 'function');
		assert.equal(typeof(m.NameServer), 'function');
		assert.equal(typeof(m.ApiServer), 'function');
		assert.equal(m.nullish(null), true);
		assert.equal(m.nullish(0), false);
		assert.match(m.ts(), /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/);
	});

	test('the modules can be required by their old paths', function() {
		// A package can require itself by name, which goes through the
		// exports map exactly like a require from a dependent package.
		let m = require('tr-ddns');
		assert.equal(require('tr-ddns/index'), m);
		assert.equal(require('tr-ddns/index.js'), m);
		for (let [ name, key ] of [ [ 'namedb', 'NameDB' ], [ 'nameserver', 'NameServer' ], [ 'apiserver', 'ApiServer' ],
									[ 'log', 'log' ], [ 'nullish', 'nullish' ], [ 'ts', 'ts' ] ]) {
			assert.equal(require('tr-ddns/' + name), m[key], name);
			assert.equal(require('tr-ddns/' + name + '.js'), m[key], name + '.js');
		}
		assert.equal(require('tr-ddns/package.json').name, 'tr-ddns');
		assert.throws(() => require('tr-ddns/lib/namedb.js'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
	});

	test('declares the command', function() {
		assert.deepEqual(pkg.bin, { 'tr-ddns': 'bin/tr-ddns' });
		for (let f of [ 'bin/tr-ddns', 'tr-ddns' ]) {
			let st = fs.statSync(path.join(ROOT, f));
			assert.ok((st.mode & 0o111) !== 0, f + ' is executable');
			assert.match(fs.readFileSync(path.join(ROOT, f), 'utf8'), /^#! ?\/usr\/bin\/env node\n/);
		}
	});

	test('the licence files are identical', function() {
		assert.equal(fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8'), fs.readFileSync(path.join(ROOT, 'MIT-RINNE'), 'utf8'));
	});

});
