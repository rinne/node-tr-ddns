'use strict';

// Keeps the documentation honest: the examples in it are run against a
// real server, the option listings are compared with the program, and
// the links between the documents are followed.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, TYPE, RCODE, startStack, runCli, tmpDir, freePort, freeTcpPort, dnsQuery } = require('./helpers');

const records = require('../lib/records');

const DOC_BASE = 'http://127.0.0.1:8080';
const REPO_URL = 'https://github.com/rinne/node-tr-ddns/blob/main/';

function read(file) {
	return fs.readFileSync(path.join(ROOT, file), 'utf8');
}

const DOCS = fs.readdirSync(path.join(ROOT, 'docs')).filter((f) => f.endsWith('.md')).map((f) => 'docs/' + f).sort();

// The command lines in the ```bash blocks of a document, in order.
function examples(file) {
	let rv = [];
	let inside = false;
	for (let line of read(file).split('\n')) {
		if (/^\s*```/.test(line)) {
			inside = (! inside) && /^\s*```bash\s*$/.test(line);
			continue;
		}
		if (inside && (line.trim() !== '')) {
			rv.push(line.trim());
		}
	}
	return rv;
}

// Splits a command line the way a shell would, for the simple quoting
// used in the documents. A comment at the end is returned separately.
function shellSplit(line) {
	let tokens = [];
	let comment = '';
	let i = 0;
	while (i < line.length) {
		if (/\s/.test(line[i])) {
			i++;
			continue;
		}
		if (line[i] === '#') {
			comment = line.slice(i + 1).trim();
			break;
		}
		let token = '';
		while ((i < line.length) && (! /\s/.test(line[i]))) {
			if (line[i] === "'") {
				let end = line.indexOf("'", i + 1);
				assert.ok(end > i, 'unbalanced quote in: ' + line);
				token += line.slice(i + 1, end);
				i = end + 1;
			} else {
				token += line[i++];
			}
		}
		tokens.push(token);
	}
	return { tokens, comment };
}

async function runCurl(line, base) {
	let { tokens, comment } = shellSplit(line);
	let init = { method: 'GET', headers: {} };
	let url;
	for (let i = 1; i < tokens.length; i++) {
		switch (tokens[i]) {
		case '-u':
			init.headers.Authorization = 'Basic ' + Buffer.from(tokens[++i]).toString('base64');
			break;
		case '-H': {
			let m = tokens[++i].match(/^([^:]+):\s*(.*)$/);
			init.headers[m[1]] = m[2];
			break;
		}
		case '-d':
			init.method = 'POST';
			init.body = tokens[++i];
			break;
		default:
			assert.ok(tokens[i].startsWith(DOC_BASE + '/'), 'unexpected argument in: ' + line);
			url = base + tokens[i].slice(DOC_BASE.length);
		}
	}
	assert.ok(url, 'no URL in: ' + line);
	let res = await fetch(url, init);
	let body = await res.json();
	let expected = /^\d{3}\b/.test(comment) ? Number.parseInt(comment) : 200;
	assert.equal(res.status, expected, line + ' -> ' + JSON.stringify(body));
	assert.equal(body.status, (expected === 200) ? 'ok' : 'error', line);
	assert.equal(body.code, expected, line);
}

async function runDig(line, dnsPort) {
	let { tokens, comment } = shellSplit(line);
	let tcp = false;
	let words = [];
	for (let i = 1; i < tokens.length; i++) {
		if (tokens[i] === '-p') {
			i++;
		} else if (tokens[i] === '+tcp') {
			tcp = true;
		} else if (tokens[i].startsWith('@')) {
			assert.equal(tokens[i], '@127.0.0.1', line);
		} else {
			words.push(tokens[i]);
		}
	}
	assert.equal(words.length, 2, 'name and type expected in: ' + line);
	assert.ok(Object.hasOwn(TYPE, words[1]), 'unknown type in: ' + line);
	let r = await dnsQuery(dnsPort, words[0], TYPE[words[1]], { tcp, timeoutMs: 300 });
	if (/^no answer/.test(comment)) {
		assert.equal(r, null, line);
		return;
	}
	assert.notEqual(r, null, line);
	if (/^NXDOMAIN/.test(comment)) {
		assert.equal(r.header.rcode, RCODE.NXDOMAIN, line);
	} else if (/^NODATA/.test(comment)) {
		assert.equal(r.header.rcode, RCODE.NOERROR, line);
		assert.equal(r.answers.length, 0, line);
	} else {
		assert.equal(r.header.rcode, RCODE.NOERROR, line);
		assert.ok(r.answers.length > 0, line);
	}
}

async function runExamples(file, setup) {
	let lines = examples(file);
	assert.ok(lines.length > 0, 'no examples in ' + file);
	let s = await startStack();
	try {
		if (setup) {
			setup(s);
		}
		for (let line of lines) {
			if (line.startsWith('curl ')) {
				await runCurl(line, s.base);
			} else if (line.startsWith('dig ')) {
				await runDig(line, s.dnsPort);
			} else {
				assert.fail('example that the test cannot run in ' + file + ': ' + line);
			}
		}
	} finally {
		await s.close();
	}
	return lines.length;
}

// The identifier GitHub gives to a heading.
function slug(heading) {
	return heading.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

function anchors(file) {
	let rv = new Set();
	let inside = false;
	for (let line of read(file).split('\n')) {
		if (/^\s*```/.test(line)) {
			inside = ! inside;
		} else if (! inside) {
			let m = line.match(/^#{1,6}\s+(.*)$/);
			if (m) {
				rv.add(slug(m[1]));
			}
		}
	}
	return rv;
}

describe('documentation', function() {

	test('the examples of the README work', async function() {
		assert.ok((await runExamples('README.md')) >= 10);
	});

	test('the examples of the API reference work', async function() {
		assert.ok((await runExamples('docs/api.md')) >= 25);
	});

	test('the examples of the DNS document work', async function() {
		await runExamples('docs/dns.md', function(s) {
			s.db.addDomain('example.com');
			s.db.set('www.example.com', { a: '192.0.2.10' });
			s.db.set('example.com', { a: '192.0.2.10', mx: '10 mail.example.com' });
		});
	});

	test('the example of the library document works', async function() {
		let m = read('docs/library.md').match(/```js\n(const \{[^\n]*\n\nasync function start\([\s\S]*?)\n```/);
		assert.ok(m, 'the example was not found');
		let start = (new Function('require', m[1] + '\nreturn start;'))(require);
		let dir = tmpDir();
		let file = path.join(dir, 'config.json');
		let dnsPort = await freePort();
		let apiPort = await freeTcpPort();
		try {
			let stop = await start(file, dnsPort, apiPort);
			let r = await dnsQuery(dnsPort, 'www.example.com', TYPE.A);
			assert.equal(r.answers.length, 2);
			assert.equal(r.answers[0].ttl, 120);
			r = await dnsQuery(dnsPort, 'example.com', TYPE.SOA, { tcp: true });
			assert.equal(r.answers[0].primary, 'ns1.example.com');
			let stats = await (await fetch('http://127.0.0.1:' + apiPort + '/stats')).json();
			assert.equal(stats.data.dns.answered, 2);
			await stop();
			let saved = JSON.parse(fs.readFileSync(file, 'utf8'));
			assert.deepEqual(saved.hosts.map((h) => h.name).sort(), [ 'ns1.example.com', 'www.example.com' ]);
			// A second start reads what the first one saved.
			stop = await start(file, dnsPort, apiPort);
			r = await dnsQuery(dnsPort, 'ns1.example.com', TYPE.A);
			assert.equal(r.answers[0].address, '192.0.2.53');
			await stop();
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('the option listings are what the program prints', async function() {
		let help = (await runCli([ '--help' ])).stdout.trimEnd();
		for (let file of [ 'README.md', 'docs/cli.md' ]) {
			assert.ok(read(file).includes('```\n' + help + '\n```'), file + ' does not have the current output of --help');
		}
	});

	test('the command line reference covers every option and environment variable', async function() {
		let help = (await runCli([ '--help' ])).stdout;
		let cli = read('docs/cli.md');
		let reference = cli.slice(cli.indexOf('## Options'));
		let options = [ ...help.matchAll(/--([a-z-]+)/g) ].map((m) => m[1]);
		assert.ok(options.length >= 20);
		for (let o of new Set(options)) {
			assert.ok(reference.includes('`--' + o), '--' + o);
			if (! [ 'config-file', 'init-config-file', 'help' ].includes(o)) {
				assert.ok(reference.includes('`TR_DDNS_OPT_' + o.toUpperCase().replaceAll('-', '_') + '`'), 'environment variable of --' + o);
			}
		}
		let program = fs.readFileSync(path.join(ROOT, 'bin', 'tr-ddns'), 'utf8');
		for (let m of reference.matchAll(/`(TR_DDNS_OPT_[A-Z_]+)`/g)) {
			assert.ok(program.includes("'" + m[1] + "'"), m[1] + ' is documented but not read by the program');
		}
	});

	test('the API reference covers every call and record type', function() {
		let api = read('docs/api.md');
		let server = fs.readFileSync(path.join(ROOT, 'lib', 'apiserver.js'), 'utf8');
		let calls = [ ...server.matchAll(/case '(\/[a-z]*)':/g) ].map((m) => m[1]);
		assert.deepEqual(calls.sort(), [ '/', '/domain', '/dump', '/flush', '/host', '/record', '/stats' ]);
		for (let c of calls) {
			assert.ok(api.includes('\n## `' + c + '`\n'), c);
		}
		for (let type of records.NAMES) {
			assert.ok(api.includes('| `' + type + '` |'), type);
			assert.ok(read('README.md').includes('`' + type + '`'), type + ' in README');
		}
	});

	test('links between the documents lead somewhere', function() {
		let files = DOCS.concat([ 'README.md', 'CHANGELOG.md' ]);
		let checked = 0;
		for (let file of files) {
			for (let m of read(file).matchAll(/\]\(([^)\s]+)\)/g)) {
				let target = m[1];
				if (target.startsWith(REPO_URL)) {
					target = path.relative(path.dirname(file), target.slice(REPO_URL.length)) || path.basename(file);
				} else if (/^[a-z]+:/.test(target)) {
					continue;
				}
				let [ rel, anchor ] = target.split('#');
				let dest = (rel === '') ? file : path.normalize(path.join(path.dirname(file), rel));
				assert.ok(fs.existsSync(path.join(ROOT, dest)), file + ' links to ' + m[1] + ', which does not exist');
				if (anchor !== undefined) {
					assert.ok(anchors(dest).has(anchor), file + ' links to ' + m[1] + ', but ' + dest + ' has no such heading');
				}
				checked++;
			}
		}
		assert.ok(checked >= 25);
	});

	test('the README links to the documents with absolute addresses', function() {
		// The README is the only document in the npm package, where
		// relative links would lead nowhere.
		let readme = read('README.md');
		for (let m of readme.matchAll(/\]\(([^)\s]+)\)/g)) {
			assert.ok(m[1].startsWith(REPO_URL), m[1]);
		}
		for (let file of DOCS) {
			assert.ok(readme.includes(REPO_URL + file), file + ' is not linked from the README');
		}
	});

	test('the changelog has an entry for the current and for every published version', function() {
		let changelog = read('CHANGELOG.md');
		let versions = [ ...changelog.matchAll(/^## (\d+\.\d+\.\d+) \((\d{4}-\d\d-\d\d|unreleased)\)$/gm) ].map((m) => m[1]);
		assert.equal([ ...changelog.matchAll(/^## /gm) ].length, versions.length, 'every heading is a version with a date');
		assert.equal(new Set(versions).size, versions.length, 'no version twice');
		// Everything published before the changelog was started.
		assert.deepEqual(versions.slice(-13), [ '1.1.1', '1.1.0', '1.0.10', '1.0.9', '1.0.8', '1.0.7', '1.0.6', '1.0.5',
												'1.0.4', '1.0.3', '1.0.2', '1.0.1', '1.0.0' ]);
		assert.ok(versions.includes('2.0.0'));
		assert.ok(versions.includes(require('../package.json').version), 'the version in package.json has an entry');
		// The changelog is in the npm package, where a relative link
		// would lead nowhere.
		for (let m of changelog.matchAll(/\]\(([^)\s]+)\)/g)) {
			assert.ok(m[1].startsWith(REPO_URL), m[1]);
		}
		assert.match(read('docs/upgrading.md'), /^# Upgrading from 1\.x to 2\.0$/m);
	});

});
