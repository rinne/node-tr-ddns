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
	'README.MD',
	'apiserver.js',
	'index.js',
	'log.js',
	'namedb.js',
	'nameserver.js',
	'nullish.js',
	'package.json',
	'tr-ddns',
	'ts.js'
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

	test('the licence files are identical', function() {
		assert.equal(fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8'), fs.readFileSync(path.join(ROOT, 'MIT-RINNE'), 'utf8'));
	});

});
