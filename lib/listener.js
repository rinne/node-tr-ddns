'use strict'

// Starting and stopping an http.Server on a TCP port or on a Unix
// domain socket.

const fsp = require('node:fs').promises;
const net = require('node:net');
const ipaddr = require('ipaddr.js');

function fail(message, code) {
	let e = new Error(message);
	e.code = code;
	return e;
}

// Whether something accepts connections on the socket file.
function alive(path) {
	return new Promise(function(resolve) {
		let c = net.connect(path);
		let done = function(v) {
			c.removeAllListeners();
			c.on('error', function() { /*NOTHING*/ });
			c.destroy();
			resolve(v);
		};
		c.setTimeout(1000, function() { done(true); });
		c.once('connect', function() { done(true); });
		c.once('error', function() { done(false); });
	});
}

// Makes the path free for a new socket. A socket file that nobody
// listens on is left over from a process that did not exit cleanly,
// and is removed. Anything else that is in the way is an error.
async function prepareSocketPath(path) {
	let st;
	try {
		st = await fsp.lstat(path);
	} catch (e) {
		if (e.code === 'ENOENT') {
			return;
		}
		throw e;
	}
	if (! st.isSocket()) {
		throw fail('The path of the socket exists and is not a socket', 'EEXIST');
	}
	if (await alive(path)) {
		throw fail('The socket is in use', 'EADDRINUSE');
	}
	await fsp.unlink(path);
}

// Starts the server. where is { port, address } or { path, mode },
// where mode is the permissions of the socket file. Resolves when
// the server is listening.
async function listen(server, where) {
	if (where.path !== undefined) {
		await prepareSocketPath(where.path);
	}
	await new Promise(function(resolve, reject) {
		let onError = function(e) { reject(e); };
		server.once('error', onError);
		let onListening = function() {
			server.removeListener('error', onError);
			resolve();
		};
		if (where.path !== undefined) {
			// The socket file is created during this call, with the
			// permissions that the umask leaves. Setting the umask for
			// the duration gives the file its final permissions from the
			// start, so that it is never open to more than it should be.
			let umask = (where.mode !== undefined) ? process.umask((~where.mode) & 0o777) : undefined;
			try {
				server.listen(where.path, onListening);
			} finally {
				if (umask !== undefined) {
					process.umask(umask);
				}
			}
		} else {
			server.listen(where.port, where.address, onListening);
		}
	});
	if ((where.path !== undefined) && (where.mode !== undefined)) {
		try {
			await fsp.chmod(where.path, where.mode);
		} catch (e) {
			await close(server, where);
			throw e;
		}
	}
}

// Stops the server and drops its connections. The socket file is
// removed.
async function close(server, where) {
	if (server.listening) {
		await new Promise(function(resolve) {
			server.close(function() { resolve(); });
			server.closeAllConnections();
		});
		if (where?.path !== undefined) {
			await fsp.unlink(where.path).catch(function() { /*NOTHING*/ });
		}
	}
}

// A file mode from an octal string such as '600' or from a number.
function parseMode(value, fallback) {
	if ((value === undefined) || (value === null)) {
		return fallback;
	}
	if ((typeof(value) === 'string') && /^[0-7]{3,4}$/.test(value)) {
		return Number.parseInt(value, 8) & 0o777;
	}
	if (Number.isSafeInteger(value) && (value >= 0) && (value <= 0o777)) {
		return value;
	}
	throw new Error('Invalid socket mode');
}

// Whether s is an IP address to listen on: IPv4 in dotted decimal only
// (ipaddr.js and the resolver also take octal, so that 010.0.0.1 would be
// 8.0.0.1, and hexadecimal, short and integer forms), or IPv6, with a zone
// ID for a link-local address and an embedded IPv4 part in dotted decimal.
function validAddress(s) {
	if (typeof(s) !== 'string') {
		return false;
	}
	if (ipaddr.IPv4.isValidFourPartDecimal(s)) {
		return true;
	}
	if (! ipaddr.IPv6.isValid(s)) {
		return false;
	}
	let tail = s.replace(/%.*$/, '');
	tail = tail.slice(tail.lastIndexOf(':') + 1);
	return (! tail.includes('.')) || ipaddr.IPv4.isValidFourPartDecimal(tail);
}

module.exports = { listen, close, parseMode, validAddress };
