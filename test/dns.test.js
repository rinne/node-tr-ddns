'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const dgram = require('node:dgram');

const { lib, TYPE, RCODE, startStack, startOfRatePeriod, freePort, captureConsole, dnsQuery } = require('./helpers');

describe('DNS server', function() {

	let s;

	before(async function() {
		s = await startStack();
		s.db.addDomain('example.com');
		s.db.set('h.example.com', { a: [ '1.2.3.4', '5.6.7.8' ], aaaa: '2001:db8::1', txt: [ 'hello', 'world' ], mx: 'mail.example.com' });
		s.db.set('long.example.com', { txt: 'x'.repeat(300) });
		s.db.set('_acme-challenge.example.com', { txt: 'token' });
	});

	after(async function() {
		await s.close();
	});

	for (let tcp of [ false, true ]) {

		describe(tcp ? 'over TCP' : 'over UDP', function() {

			test('answers A', async function() {
				let r = await s.query('h.example.com', TYPE.A, { tcp });
				assert.equal(r.header.qr, 1);
				assert.equal(r.header.rcode, RCODE.NOERROR);
				assert.deepEqual(r.answers.map((a) => a.address).sort(), [ '1.2.3.4', '5.6.7.8' ]);
				for (let a of r.answers) {
					assert.equal(a.type, TYPE.A);
					assert.equal(a.ttl, 60);
					assert.equal(a.name, 'h.example.com');
				}
			});

			test('answers AAAA', async function() {
				let r = await s.query('h.example.com', TYPE.AAAA, { tcp });
				assert.deepEqual(r.answers.map((a) => a.address), [ '2001:db8::1' ]);
			});

			test('answers TXT', async function() {
				let r = await s.query('h.example.com', TYPE.TXT, { tcp });
				assert.deepEqual(r.answers.map((a) => a.data).sort(), [ [ 'hello' ], [ 'world' ] ]);
				r = await s.query('_acme-challenge.example.com', TYPE.TXT, { tcp });
				assert.deepEqual(r.answers.map((a) => a.data), [ [ 'token' ] ]);
			});

			test('answers MX', async function() {
				let r = await s.query('h.example.com', TYPE.MX, { tcp });
				assert.deepEqual(r.answers.map((a) => a.exchange), [ 'mail.example.com' ]);
			});

			test('answers a TXT value longer than 255 bytes', async function() {
				let r = await s.query('long.example.com', TYPE.TXT, { tcp, edns: true });
				assert.equal(r.answers.length, 1);
				// One record of two character strings, the first one full.
				assert.deepEqual(r.answers[0].data, [ 'x'.repeat(255), 'x'.repeat(45) ]);
			});

			test('answers SOA and NS at the apex', async function() {
				let r = await s.query('example.com', TYPE.SOA, { tcp });
				assert.equal(r.answers.length, 1);
				assert.equal(r.answers[0].primary, 'example.com');
				r = await s.query('example.com', TYPE.NS, { tcp });
				assert.deepEqual(r.answers.map((a) => a.ns), [ 'example.com' ]);
			});

			test('names are case insensitive and the question is echoed', async function() {
				let r = await s.query('H.ExAmPlE.CoM', TYPE.A, { tcp });
				assert.equal(r.answers.length, 2);
				assert.equal(r.questions.length, 1);
				assert.equal(r.questions[0].name, 'H.ExAmPlE.CoM');
			});

			test('gives an empty answer for a served name without data', async function() {
				let r = await s.query('h.example.com', TYPE.SRV, { tcp });
				assert.equal(r.header.rcode, RCODE.NOERROR);
				assert.equal(r.answers.length, 0);
			});

			test('stays silent for names outside the served domains', async function() {
				assert.equal(await s.query('h.example.org', TYPE.A, { tcp, timeoutMs: 250 }), null);
				assert.equal(await s.query('com', TYPE.NS, { tcp, timeoutMs: 250 }), null);
			});

			test('stays silent for classes other than IN', async function() {
				assert.equal(await s.query('h.example.com', TYPE.A, { tcp, 'class': 3, timeoutMs: 250 }), null);
			});

			test('answers query types it has no data for', async function() {
				for (let type of [ TYPE.HTTPS, TYPE.SVCB, TYPE.DS, 99, 65280 ]) {
					let r = await s.query('h.example.com', type, { tcp, timeoutMs: 250 });
					assert.notEqual(r, null, 'type ' + type);
					assert.equal(r.header.rcode, RCODE.NOERROR);
					assert.equal(r.answers.length, 0);
				}
			});

			test('stays silent for packets that are not plain queries', async function() {
				assert.equal(await s.query('h.example.com', TYPE.A, { tcp, qr: 1, timeoutMs: 250 }), null, 'response');
				assert.equal(await s.query('h.example.com', TYPE.A, { tcp, opcode: 5, timeoutMs: 250 }), null, 'UPDATE');
				assert.equal(await s.query('h.example.com', TYPE.A, { tcp, opcode: 4, timeoutMs: 250 }), null, 'NOTIFY');
				assert.equal(await s.query('h.example.com', TYPE.A, { tcp, extraQuestions: [ { name: 'h.example.com', type: TYPE.AAAA } ], timeoutMs: 250 }), null, 'two questions');
			});

			test('answers a served name that is not a valid host name', async function() {
				for (let name of [ 'bad_label.x.example.com', '-x.example.com', 'a b.example.com' ]) {
					let r = await s.query(name, TYPE.A, { tcp, timeoutMs: 250 });
					assert.notEqual(r, null, name);
					assert.equal(r.header.rcode, RCODE.NXDOMAIN, name);
					assert.equal(r.answers.length, 0);
				}
				assert.equal(await s.query('bad_label.x.example.org', TYPE.A, { tcp, timeoutMs: 250 }), null);
			});

		});

	}

	describe('response details', function() {

		test('answers are authoritative', async function() {
			for (let [ name, type ] of [ [ 'h.example.com', TYPE.A ], [ 'h.example.com', TYPE.SRV ], [ 'nothing.example.com', TYPE.A ], [ 'example.com', TYPE.SOA ] ]) {
				let r = await s.query(name, type);
				assert.equal(r.header.aa, 1, name);
				assert.equal(r.header.ra, 0);
				assert.equal(r.header.rd, 1, 'the RD bit is copied from the query');
			}
		});

		test('a name that does not exist gives NXDOMAIN with the SOA in the authority section', async function() {
			let r = await s.query('nothing.example.com', TYPE.A);
			assert.equal(r.header.rcode, RCODE.NXDOMAIN);
			assert.equal(r.answers.length, 0);
			assert.equal(r.authorities.length, 1);
			assert.equal(r.authorities[0].type, TYPE.SOA);
			assert.equal(r.authorities[0].name, 'example.com');
			assert.equal(r.authorities[0].ttl, 10);
			assert.equal(r.authorities[0].minimum, 10);
		});

		test('a name without the type asked gives no data with the SOA in the authority section', async function() {
			for (let type of [ TYPE.SRV, TYPE.HTTPS, TYPE.CNAME ]) {
				let r = await s.query('h.example.com', type);
				assert.equal(r.header.rcode, RCODE.NOERROR);
				assert.equal(r.answers.length, 0);
				assert.deepEqual(r.authorities.map((a) => a.type), [ TYPE.SOA ]);
			}
		});

		test('an OPT record is returned to a client that sent one, and only then', async function() {
			let r = await s.query('h.example.com', TYPE.A, { edns: true });
			let opt = r.additionals.filter((a) => (a.type === TYPE.EDNS));
			assert.equal(opt.length, 1);
			assert.equal(opt[0]['class'], 1232, 'the UDP payload size offered');
			r = await s.query('nothing.example.com', TYPE.A, { edns: true, tcp: true });
			assert.equal(r.additionals.filter((a) => (a.type === TYPE.EDNS)).length, 1);
			r = await s.query('h.example.com', TYPE.A);
			assert.equal(r.additionals.length, 0);
		});

	});

	describe('record types', function() {

		test('MX with priorities', async function() {
			s.db.set('mail.example.com', { mx: [ '10 mx1.example.com', '20 mx2.example.com' ] });
			let r = await s.query('mail.example.com', TYPE.MX);
			assert.deepEqual(r.answers.map((a) => [ a.priority, a.exchange ]), [ [ 10, 'mx1.example.com' ], [ 20, 'mx2.example.com' ] ]);
		});

		test('SRV', async function() {
			s.db.set('_sip._tcp.example.com', { srv: '10 5 5060 sip.example.com' });
			let r = await s.query('_sip._tcp.example.com', TYPE.SRV, { tcp: true });
			assert.deepEqual(r.answers.map((a) => [ a.priority, a.weight, a.port, a.target ]), [ [ 10, 5, 5060, 'sip.example.com' ] ]);
		});

		test('CAA', async function() {
			s.db.set('caa.example.com', { caa: '0 issue letsencrypt.org' });
			let r = await s.query('caa.example.com', TYPE.CAA);
			assert.deepEqual(r.answers.map((a) => [ a.flags, a.tag, a.value ]), [ [ 0, 'issue', 'letsencrypt.org' ] ]);
		});

		test('CNAME with the records of the target', async function() {
			s.db.set('alias.example.com', { cname: 'h.example.com' });
			let r = await s.query('alias.example.com', TYPE.A);
			assert.equal(r.header.aa, 1);
			assert.deepEqual(r.answers.map((a) => a.type), [ TYPE.CNAME, TYPE.A, TYPE.A ]);
			assert.equal(r.answers[0].domain, 'h.example.com');
			r = await s.query('alias.example.com', TYPE.CNAME);
			assert.deepEqual(r.answers.map((a) => a.domain), [ 'h.example.com' ]);
		});

		test('a delegation is answered with a referral', async function() {
			s.db.set('sub.example.com', { ns: 'ns.sub.example.com' });
			s.db.set('ns.sub.example.com', { a: '192.0.2.53' });
			let r = await s.query('www.sub.example.com', TYPE.A);
			assert.equal(r.header.rcode, RCODE.NOERROR);
			assert.equal(r.header.aa, 0);
			assert.equal(r.answers.length, 0);
			assert.deepEqual(r.authorities.map((a) => [ a.name, a.type, a.ns ]), [ [ 'sub.example.com', TYPE.NS, 'ns.sub.example.com' ] ]);
			assert.deepEqual(r.additionals.map((a) => [ a.name, a.address ]), [ [ 'ns.sub.example.com', '192.0.2.53' ] ]);
		});

		test('the settings of a domain show in SOA, NS and the ttl of records', async function() {
			s.db.addDomain('settings.test', { ns: [ 'ns1.settings.test', 'ns2.example.net' ], admin: 'hostmaster@settings.test',
											  ttl: 300, refresh: 7200, retry: 900, expiration: 1209600, minimum: 60 });
			s.db.set('ns1.settings.test', { a: '192.0.2.1' });
			let r = await s.query('settings.test', TYPE.SOA);
			let soa = r.answers[0];
			assert.deepEqual([ soa.primary, soa.admin, soa.ttl, soa.refresh, soa.retry, soa.expiration, soa.minimum ],
							 [ 'ns1.settings.test', 'hostmaster.settings.test', 300, 7200, 900, 1209600, 60 ]);
			r = await s.query('settings.test', TYPE.NS);
			assert.deepEqual(r.answers.map((a) => a.ns), [ 'ns1.settings.test', 'ns2.example.net' ]);
			assert.deepEqual(r.additionals.map((a) => a.address), [ '192.0.2.1' ]);
			r = await s.query('ns1.settings.test', TYPE.A);
			assert.equal(r.answers[0].ttl, 300);
			r = await s.query('nothing.settings.test', TYPE.A);
			assert.equal(r.authorities[0].ttl, 60);
		});

	});

	test('truncates over UDP when the answer does not fit', async function() {
		let many = [];
		for (let i = 0; i < 60; i++) {
			many.push('10.0.0.' + i);
		}
		s.db.set('many.example.com', { a: many });
		let r = await s.query('many.example.com', TYPE.A);
		assert.equal(r.header.tc, 1);
		assert.equal(r.answers.length, 0);
		r = await s.query('many.example.com', TYPE.A, { tcp: true });
		assert.equal(r.header.tc, 0);
		assert.equal(r.answers.length, 60);
	});

	test('garbage does not stop the server', async function() {
		let lines = await captureConsole(async function() {
			let sock = dgram.createSocket('udp4');
			for (let b of [ Buffer.from([ 1 ]), Buffer.alloc(11), Buffer.from('hello world, this is not dns'), Buffer.alloc(600, 0xff) ]) {
				sock.send(b, s.dnsPort, '127.0.0.1');
			}
			await new Promise((r) => setTimeout(r, 100));
			sock.close();
		});
		void lines;
		let r = await s.query('h.example.com', TYPE.A);
		assert.equal(r.answers.length, 2);
	});

	test('queries that get no answer are not logged', async function() {
		let lines = await captureConsole(async function() {
			await s.query('h.example.org', TYPE.A, { timeoutMs: 100 });
			await s.query('nothing.example.com', TYPE.A);
			await s.query('h.example.com', TYPE.A, { qr: 1, timeoutMs: 100 });
		});
		assert.deepEqual(lines, []);
	});

	test('counts queries by outcome', async function() {
		let a = s.ns.stats();
		await s.query('h.example.com', TYPE.A);
		await s.query('h.example.com', TYPE.SRV);
		await s.query('nothing.example.com', TYPE.A);
		await s.query('h.example.org', TYPE.A, { timeoutMs: 100 });
		await s.query('h.example.com', TYPE.A, { qr: 1, timeoutMs: 100 });
		await s.query('h.example.com', TYPE.A, { 'class': 3, timeoutMs: 100 });
		let b = s.ns.stats();
		assert.equal(b.queries - a.queries, 6);
		assert.equal(b.answered - a.answered, 3);
		assert.equal(b.empty - a.empty, 1);
		assert.equal(b.nxdomain - a.nxdomain, 1);
		assert.equal(b.dropped.outOfZone - a.dropped.outOfZone, 1);
		assert.equal(b.dropped.notQuery - a.dropped.notQuery, 1);
		assert.equal(b.dropped.invalid - a.dropped.invalid, 1);
		assert.equal(b.dropped.rateLimited, 0);
	});

	test('lookups are counted', async function() {
		let before = s.db.stats().lookup.total;
		await s.query('h.example.com', TYPE.A);
		assert.equal(s.db.stats().lookup.total, before + 1);
	});

});

describe('DNS server that refuses', function() {

	test('answers REFUSED outside the served domains when asked to', async function() {
		let s = await startStack({ dns: { refuseOutOfZone: true } });
		try {
			s.db.addDomain('example.com');
			s.db.set('h.example.com', { a: '1.2.3.4' });
			for (let tcp of [ false, true ]) {
				let r = await s.query('h.example.org', TYPE.A, { tcp });
				assert.notEqual(r, null);
				assert.equal(r.header.rcode, RCODE.REFUSED);
				assert.equal(r.header.aa, 0);
				assert.equal(r.answers.length + r.authorities.length + r.additionals.length, 0);
				assert.equal((await s.query('h.example.com', TYPE.A, { tcp })).header.rcode, RCODE.NOERROR);
			}
			assert.equal(await s.query('h.example.org', TYPE.A, { qr: 1, timeoutMs: 100 }), null, 'what is not a query is still ignored');
			let st = s.ns.stats();
			assert.equal(st.refused, 2);
			assert.equal(st.dropped.outOfZone, 0);
		} finally {
			await s.close();
		}
	});

});

describe('DNS server on several addresses', function() {

	// Whether this machine has the IPv6 loopback address.
	async function hasIpv6() {
		return new Promise(function(resolve) {
			let sock = dgram.createSocket('udp6');
			sock.once('error', function() { resolve(false); });
			sock.bind(0, '::1', function() { sock.close(function() { resolve(true); }); });
		});
	}

	test('listens on every address of a list', async function(t) {
		if (! (await hasIpv6())) {
			t.skip('no IPv6 loopback address');
			return;
		}
		let db = new lib.NameDB();
		db.addDomain('example.com');
		db.set('h.example.com', { a: '1.2.3.4' });
		let port = await freePort();
		for (let addresses of [ [ '127.0.0.1', '::1' ], '127.0.0.1, ::1' ]) {
			let ns = new lib.NameServer({ nameDB: db, udp: true, udpListenPort: port, udpListenAddress: addresses,
										  tcp: true, tcpListenPort: port, tcpListenAddress: addresses });
			await once(ns, 'ready');
			try {
				for (let address of [ '127.0.0.1', '::1' ]) {
					for (let tcp of [ false, true ]) {
						let r = await dnsQuery(port, 'h.example.com', TYPE.A, { address, tcp });
						assert.equal(r.answers.length, 1, address + (tcp ? ' tcp' : ' udp'));
					}
				}
			} finally {
				let closed = once(ns, 'close');
				await ns.close();
				await closed;
			}
		}
		db.close();
	});

	test('one address that cannot be used stops all of them', async function() {
		let db = new lib.NameDB();
		let port = await freePort();
		let blocker = require('node:net').createServer();
		await new Promise((r) => blocker.listen(port, '127.0.0.1', r));
		let ns = new lib.NameServer({ nameDB: db, udp: true, udpListenPort: port, udpListenAddress: '127.0.0.1',
									  tcp: true, tcpListenPort: port, tcpListenAddress: '127.0.0.1' });
		try {
			let [ e ] = await once(ns, 'error');
			assert.equal(e.code, 'EADDRINUSE');
			await new Promise((r) => setTimeout(r, 50));
			assert.equal(await dnsQuery(port, 'example.com', TYPE.SOA, { timeoutMs: 100 }), null, 'the UDP listener is closed too');
		} finally {
			await ns.close();
			blocker.close();
			db.close();
		}
	});

	test('an invalid list is refused', function() {
		let db = new lib.NameDB();
		try {
			for (let bad of [ '', '127.0.0.1,', '127.0.0.1,nope', [], [ '127.0.0.1', 7 ], 7 ]) {
				assert.throws(() => new lib.NameServer({ nameDB: db, udp: true, udpListenAddress: bad }), /UDP listen address/, JSON.stringify(bad));
				assert.throws(() => new lib.NameServer({ nameDB: db, tcp: true, tcpListenAddress: bad }), /TCP listen address/, JSON.stringify(bad));
			}
		} finally {
			db.close();
		}
	});

});

describe('DNS rate limiting', function() {

	test('queries over the limit from one source are not answered', async function() {
		let s = await startStack({ dns: { rateLimit: 5 } });
		try {
			s.db.addDomain('example.com');
			s.db.set('h.example.com', { a: '1.2.3.4' });
			await startOfRatePeriod((ms) => s.query('h.example.com', TYPE.A, { timeoutMs: ms }));
			// One query of this second has been answered already.
			let results = [];
			for (let i = 0; i < 10; i++) {
				results.push(await s.query('h.example.com', TYPE.A, { timeoutMs: 40, tcp: ((i % 2) === 1) }));
			}
			assert.deepEqual(results.map((r) => (r !== null)), [ true, true, true, true, false, false, false, false, false, false ]);
			assert.ok(s.ns.stats().dropped.rateLimited >= 6);
			await new Promise((r) => setTimeout(r, 1100));
			assert.notEqual(await s.query('h.example.com', TYPE.A), null, 'answers again in the next second');
		} finally {
			await s.close();
		}
	});

	test('the limit can be switched off', async function() {
		let s = await startStack({ dns: { rateLimit: 0 } });
		try {
			s.db.addDomain('example.com');
			s.db.set('h.example.com', { a: '1.2.3.4' });
			let answered = 0;
			for (let i = 0; i < 700; i++) {
				if ((await s.query('h.example.com', TYPE.A)) !== null) {
					answered++;
				}
			}
			assert.equal(answered, 700);
			assert.equal(s.ns.stats().dropped.rateLimited, 0);
		} finally {
			await s.close();
		}
	});

	test('the default is a limit of 500 queries per second', function() {
		assert.equal(lib.NameServer.DEFAULT_RATE_LIMIT, 500);
	});

	test('an invalid limit is refused', function() {
		let db = new lib.NameDB();
		try {
			for (let bad of [ -1, 1.5, 'many', true ]) {
				assert.throws(() => new lib.NameServer({ nameDB: db, udp: true, rateLimit: bad }), /rate limit/);
			}
		} finally {
			db.close();
		}
	});

});

describe('NameServer', function() {

	test('requires a database and at least one listener', function() {
		let db = new lib.NameDB();
		try {
			assert.throws(() => new lib.NameServer({ udp: true }), /NameDB/);
			assert.throws(() => new lib.NameServer({ nameDB: db }), /No listeners/);
			assert.throws(() => new lib.NameServer({ nameDB: db, udp: true, udpListenAddress: 'bogus' }), /address/);
			assert.throws(() => new lib.NameServer({ nameDB: db, tcp: true, tcpListenPort: 70000 }), /port/);
		} finally {
			db.close();
		}
	});

	test('emits ready and close', async function() {
		let db = new lib.NameDB();
		let port = await freePort();
		let ns = new lib.NameServer({ nameDB: db, udp: true, udpListenPort: port, udpListenAddress: '127.0.0.1' });
		await once(ns, 'ready');
		let closed = once(ns, 'close');
		await ns.close();
		await closed;
		db.close();
	});

	test('reports a failed bind as an error event', async function() {
		let db = new lib.NameDB();
		let port = await freePort();
		let blocker = dgram.createSocket('udp4');
		await new Promise((r) => blocker.bind(port, '127.0.0.1', r));
		let ns = new lib.NameServer({ nameDB: db, udp: true, udpListenPort: port, udpListenAddress: '127.0.0.1' });
		try {
			let got = await Promise.race([
				once(ns, 'error').then((a) => a[0]),
				new Promise((r) => setTimeout(() => r(null), 500))
			]);
			assert.ok(got instanceof Error);
			assert.equal(got.code, 'EADDRINUSE');
		} finally {
			await ns.close();
			blocker.close();
			db.close();
		}
	});

});
