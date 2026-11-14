'use strict';

// Shared test plumbing: locations of the code under test, free port
// allocation, a minimal DNS client that exposes the raw response, and
// helpers for the HTTP API and the command line program.

const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const { Packet } = require('dns2');

const ROOT = path.resolve(__dirname, '..');
const LIB = path.join(ROOT, 'lib');
const CLI = path.join(ROOT, 'bin', 'tr-ddns');
const LAUNCHER = path.join(ROOT, 'tr-ddns');

const lib = require(path.join(LIB, 'index.js'));

const TYPE = Object.assign({}, Packet.TYPE, { HTTPS: 65, SVCB: 64, DS: 43 });
const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

function freeTcpPort() {
	return new Promise(function(resolve, reject) {
		let s = net.createServer();
		s.once('error', reject);
		s.listen(0, '127.0.0.1', function() {
			let port = s.address().port;
			s.close(function() { resolve(port); });
		});
	});
}

function freeUdpPort() {
	return new Promise(function(resolve, reject) {
		let s = dgram.createSocket('udp4');
		s.once('error', reject);
		s.bind(0, '127.0.0.1', function() {
			let port = s.address().port;
			s.close(function() { resolve(port); });
		});
	});
}

// A port that is free for both TCP and UDP on the loopback interface.
async function freePort() {
	for (let i = 0; i < 50; i++) {
		let port = await freeTcpPort();
		let ok = await new Promise(function(resolve) {
			let s = dgram.createSocket('udp4');
			s.once('error', function() { resolve(false); });
			s.bind(port, '127.0.0.1', function() { s.close(function() { resolve(true); }); });
		});
		if (ok) {
			return port;
		}
	}
	throw new Error('Unable to find a free port');
}

function buildQuery(name, type, opts) {
	let p = new Packet();
	p.header.id = opts?.id ?? (1 + Math.floor(Math.random() * 65534));
	p.header.rd = opts?.rd ?? 1;
	p.header.qr = opts?.qr ?? 0;
	p.header.opcode = opts?.opcode ?? 0;
	p.questions.push({ name: name, type: type, 'class': opts?.['class'] ?? Packet.CLASS.IN });
	for (let q of (opts?.extraQuestions ?? [])) {
		p.questions.push({ name: q.name, type: q.type, 'class': Packet.CLASS.IN });
	}
	if (opts?.edns) {
		p.additionals.push(Packet.Resource.EDNS([]));
	}
	return p.toBuffer();
}

// Sends a datagram and resolves to the raw response, or to null when
// nothing arrives within the timeout.
function udpExchange(port, buffer, timeoutMs, address) {
	return new Promise(function(resolve, reject) {
		let s = dgram.createSocket((address && address.includes(':')) ? 'udp6' : 'udp4');
		let timer = setTimeout(function() { s.close(); resolve(null); }, timeoutMs ?? 400);
		s.once('error', function(e) { clearTimeout(timer); s.close(); reject(e); });
		s.once('message', function(m) { clearTimeout(timer); s.close(); resolve(m); });
		s.send(buffer, port, address ?? '127.0.0.1');
	});
}

function tcpExchange(port, buffer, timeoutMs, address) {
	return new Promise(function(resolve, reject) {
		let chunks = [];
		let done = false;
		let c = net.connect(port, address ?? '127.0.0.1');
		let finish = function(v) {
			if (done) {
				return;
			}
			done = true;
			clearTimeout(timer);
			c.destroy();
			resolve(v);
		};
		let timer = setTimeout(function() { finish(null); }, timeoutMs ?? 400);
		c.once('error', function(e) { if (! done) { done = true; clearTimeout(timer); reject(e); } });
		c.on('connect', function() {
			let len = Buffer.alloc(2);
			len.writeUInt16BE(buffer.length);
			c.write(Buffer.concat([ len, buffer ]));
		});
		c.on('data', function(d) {
			chunks.push(d);
			let all = Buffer.concat(chunks);
			if ((all.length >= 2) && (all.length >= (2 + all.readUInt16BE(0)))) {
				finish(all.subarray(2, 2 + all.readUInt16BE(0)));
			}
		});
		c.on('close', function() { finish(null); });
	});
}

// Asks one question. Resolves to the parsed response packet (with the
// raw bytes in .raw), or to null when the server stays silent.
async function dnsQuery(port, name, type, opts) {
	let q = buildQuery(name, type, opts);
	let raw = await (opts?.tcp ? tcpExchange : udpExchange)(port, q, opts?.timeoutMs, opts?.address);
	if (raw === null) {
		return null;
	}
	let p = Packet.parse(raw);
	p.raw = raw;
	return p;
}

// HTTP API call. GET with query parameters by default; with opts.json
// the parameters are sent as a JSON body in a POST.
async function apiCall(base, urlPath, params, opts) {
	let url = base + urlPath;
	let init = { method: opts?.method ?? 'GET', headers: Object.assign({}, opts?.headers) };
	if (opts?.json) {
		init.method = opts?.method ?? 'POST';
		init.headers['Content-Type'] = 'application/json';
		init.body = JSON.stringify(params ?? {});
	} else if (opts?.rawBody !== undefined) {
		init.body = opts.rawBody;
	} else if (params) {
		let u = new URLSearchParams();
		for (let [ k, v ] of Object.entries(params)) {
			for (let x of (Array.isArray(v) ? v : [ v ])) {
				u.append(k, x);
			}
		}
		let qs = u.toString();
		if (qs !== '') {
			url += '?' + qs;
		}
	}
	if (opts?.auth) {
		init.headers.Authorization = 'Basic ' + Buffer.from(opts.auth).toString('base64');
	}
	let res = await fetch(url, init);
	let text = await res.text();
	let body;
	try {
		body = JSON.parse(text);
	} catch (e) {
		body = undefined;
	}
	return { status: res.status, body: body, text: text, headers: res.headers };
}

// Runs fn with console.log, console.warn and console.error captured.
// Returns the captured lines.
async function captureConsole(fn) {
	let lines = [];
	let saved = { log: console.log, warn: console.warn, error: console.error };
	for (let k of Object.keys(saved)) {
		console[k] = function(...av) { lines.push(av.map((x) => ((typeof(x) === 'string') ? x : require('node:util').inspect(x))).join(' ')); };
	}
	try {
		await fn();
	} finally {
		Object.assign(console, saved);
	}
	return lines;
}

// Starts the three components on loopback ports. opts.db, opts.dns
// and opts.api are merged into the respective constructor options.
async function startStack(opts) {
	let db = new lib.NameDB(Object.assign({}, opts?.db));
	let dnsPort = await freePort();
	let apiPort = await freeTcpPort();
	let ns = new lib.NameServer(Object.assign({ nameDB: db,
												udp: true,
												udpListenPort: dnsPort,
												udpListenAddress: '127.0.0.1',
												tcp: true,
												tcpListenPort: dnsPort,
												tcpListenAddress: '127.0.0.1' },
											  opts?.dns));
	await once(ns, 'ready');
	let api = new lib.ApiServer(Object.assign({ nameDB: db, port: apiPort, address: '127.0.0.1' }, opts?.api));
	let base = 'http://127.0.0.1:' + apiPort;
	for (let i = 0; i < 100; i++) {
		try {
			await fetch(base + '/');
			break;
		} catch (e) {
			await new Promise((r) => setTimeout(r, 20));
		}
	}
	return {
		db, ns, api, dnsPort, apiPort, base,
		call: function(urlPath, params, o) { return apiCall(base, urlPath, params, o); },
		query: function(name, type, o) { return dnsQuery(dnsPort, name, type, o); },
		close: async function() {
			await api.close();
			await ns.close();
			db.close();
		}
	};
}

function tmpDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), 'tr-ddns-test-'));
}

// Runs the command line program to completion.
function runCli(args, opts) {
	return new Promise(function(resolve, reject) {
		let env = Object.assign({}, process.env, opts?.env);
		for (let k of Object.keys(env)) {
			if (k.startsWith('TR_DDNS_OPT_') && (! (opts?.env && (k in opts.env)))) {
				delete env[k];
			}
		}
		let c = spawn(process.execPath, [ opts?.cli ?? CLI ].concat(args), { env: env, stdio: [ 'ignore', 'pipe', 'pipe' ] });
		let stdout = '', stderr = '';
		c.stdout.on('data', function(d) { stdout += d; });
		c.stderr.on('data', function(d) { stderr += d; });
		// A program that was expected to exit but keeps running is
		// killed, and the test sees the signal.
		let timer = setTimeout(function() { c.kill('SIGKILL'); }, opts?.timeoutMs ?? 10000);
		c.on('error', function(e) { clearTimeout(timer); reject(e); });
		c.on('close', function(code, signal) { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
	});
}

// Starts the command line program as a server and waits until its HTTP
// API answers. Returns a handle with stop() and the collected output.
async function startCli(args, opts) {
	let env = Object.assign({}, process.env, opts?.env);
	for (let k of Object.keys(env)) {
		if (k.startsWith('TR_DDNS_OPT_') && (! (opts?.env && (k in opts.env)))) {
			delete env[k];
		}
	}
	let c = spawn(process.execPath, [ opts?.cli ?? CLI ].concat(args), { env: env, stdio: [ 'ignore', 'pipe', 'pipe' ] });
	let h = { child: c, stdout: '', stderr: '', exited: false, code: null, signal: null };
	c.stdout.on('data', function(d) { h.stdout += d; });
	c.stderr.on('data', function(d) { h.stderr += d; });
	h.closed = new Promise(function(resolve) {
		c.on('close', function(code, signal) { h.exited = true; h.code = code; h.signal = signal; resolve(h); });
	});
	h.stop = async function(signal) {
		if (! h.exited) {
			c.kill(signal ?? 'SIGTERM');
		}
		return h.closed;
	};
	if (opts?.waitUrl) {
		let ok = false;
		for (let i = 0; (i < 250) && (! h.exited); i++) {
			try {
				await fetch(opts.waitUrl, opts?.waitInit);
				ok = true;
				break;
			} catch (e) {
				await new Promise((r) => setTimeout(r, 20));
			}
		}
		if (! ok) {
			await h.stop('SIGKILL');
			throw new Error('Server did not start: ' + h.stdout + h.stderr);
		}
	}
	return h;
}

async function waitFor(fn, timeoutMs) {
	let end = Date.now() + (timeoutMs ?? 3000);
	while (true) {
		let v = await fn();
		if (v) {
			return v;
		}
		if (Date.now() > end) {
			throw new Error('Condition not met in time');
		}
		await new Promise((r) => setTimeout(r, 20));
	}
}

module.exports = {
	ROOT, LIB, CLI, LAUNCHER, lib, Packet, TYPE, RCODE,
	freePort, freeTcpPort, freeUdpPort,
	buildQuery, udpExchange, tcpExchange, dnsQuery,
	apiCall, captureConsole, startStack, tmpDir, runCli, startCli, waitFor
};
