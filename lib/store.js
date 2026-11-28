'use strict'

// Keeps the contents of a NameDB in a JSON file: reads the file into
// the database at startup and writes the database back when it
// changes.

const EventEmitter = require('node:events');
const fsp = require('node:fs').promises;
const path = require('node:path');

const nullish = require('./nullish');

class ConfigError extends Error {
	constructor(message, code) {
		super(message);
		this.code = code;
	}
}

class ConfigStore extends EventEmitter {

	#file;
	#db;
	#intervalMs;
	#lastWrite;
	#timer;
	#dirty;
	#writing;
	#listeners;

	// config.file           the configuration file
	// config.nameDB         the database to load into and to save
	// config.writeIntervalMs  the shortest time between two writes
	//                       (default 10000); changes made sooner are
	//                       written together when the time is up
	constructor(config) {
		super();
		if (! ((typeof(config?.file) === 'string') && (config.file !== ''))) {
			throw new Error('Invalid configuration file name');
		}
		if (! (typeof(config?.nameDB?.dump) === 'function')) {
			throw new Error('Invalid NameDB');
		}
		let intervalMs = config?.writeIntervalMs ?? 10000;
		if (! (Number.isSafeInteger(intervalMs) && (intervalMs >= 0))) {
			throw new Error('Invalid write interval');
		}
		this.#file = config.file;
		this.#db = config.nameDB;
		this.#intervalMs = intervalMs;
		this.#lastWrite = 0;
		this.#timer = null;
		this.#dirty = false;
		this.#writing = null;
		this.#listeners = null;
	}

	// Creates the file from the current contents of the database.
	// Fails with code EEXIST if the file is already there.
	async init() {
		let data = JSON.stringify(this.#db.dump(), null, 2);
		await fsp.writeFile(this.#file, data, { encoding: 'utf8', mode: 0o644, flag: 'wx' });
	}

	// Reads the file into the database. Entries that cannot be used
	// are skipped, and a message about each is returned in an array.
	// Throws a ConfigError with code ENOENT when there is no file,
	// EMALFORMED when the file is not a configuration, or the code of
	// the file system error.
	async load() {
		let text;
		try {
			text = await fsp.readFile(this.#file, { encoding: 'utf8', flag: 'r' });
		} catch (e) {
			throw new ConfigError('Unable to access configuration file', e?.code ?? '?');
		}
		let config;
		try {
			config = JSON.parse(text);
		} catch (e) {
			config = undefined;
		}
		if (! (Array.isArray(config?.domains) && Array.isArray(config?.hosts))) {
			throw new ConfigError('Malformatted configuration', 'EMALFORMED');
		}
		let warnings = [];
		for (let d of config.domains) {
			let label = (typeof(d?.name) === 'string') ? d.name : '?';
			if (! this.#db.validDomain(d?.name)) {
				warnings.push('Ignored invalid domain entry (' + label + ') from configuration.');
				continue;
			}
			let options = { serial: d.serial };
			for (let k of [ 'ns', 'admin', 'ttl', 'refresh', 'retry', 'expiration', 'minimum' ]) {
				if (! nullish(d[k])) {
					options[k] = d[k];
				}
			}
			try {
				this.#db.addDomain(d.name, options);
			} catch (e) {
				if (! /^Invalid domain setting/.test(e?.message)) {
					warnings.push('Ignored domain entry (' + label + ') that cannot be activated from configuration.');
					continue;
				}
				// The domain itself is fine. It is served with the default
				// settings instead of losing all of its hosts.
				try {
					this.#db.addDomain(d.name, { serial: d.serial });
					warnings.push('Ignored invalid settings of domain entry (' + label + ') in configuration.');
				} catch (e2) {
					warnings.push('Ignored domain entry (' + label + ') that cannot be activated from configuration.');
				}
			}
		}
		let now = Date.now();
		for (let h of config.hosts) {
			let label = (typeof(h?.name) === 'string') ? h.name : '?';
			if (! this.#db.valid(h?.name)) {
				warnings.push('Ignored invalid host entry (' + label + ') from configuration.');
				continue;
			}
			let ttlMs;
			if (Number.isFinite(h.expires)) {
				if (h.expires <= now) {
					continue;
				}
				ttlMs = Math.ceil(h.expires - now);
			} else if (! nullish(h.expires)) {
				warnings.push('Ignored invalid host entry (' + label + ') from configuration.');
				continue;
			}
			let ok;
			try {
				ok = this.#db.set(h.name, h.data, ttlMs);
			} catch (e) {
				ok = false;
			}
			if (! ok) {
				warnings.push('Ignored invalid host entry (' + label + ') that cannot be activated from configuration.');
			}
		}
		return warnings;
	}

	// Writes the database to the file now. The new contents go to a
	// temporary file that then replaces the old file in one step, so
	// that a crash or a full disk cannot leave half a file behind.
	//
	// With options.untimed the write does not count for the write
	// interval. It is meant for the write at startup, after which the
	// first change is still written at once.
	async write(options) {
		while (this.#writing) {
			await this.#writing.catch(function() { /*NOTHING*/ });
		}
		this.#dirty = false;
		if (! options?.untimed) {
			this.#lastWrite = Date.now();
		}
		this.#writing = this.#writeFile(JSON.stringify(this.#db.dump(), null, 2));
		try {
			await this.#writing;
		} finally {
			this.#writing = null;
		}
		this.emit('write');
	}

	async #writeFile(data) {
		let target = this.#file;
		let mode = 0o644;
		try {
			// A symbolic link stays a link, and the permissions of an
			// existing file are kept.
			target = await fsp.realpath(this.#file);
			mode = (await fsp.stat(target)).mode & 0o777;
		} catch (e) {
			/*NOTHING*/
		}
		let tmp = path.join(path.dirname(target), '.' + path.basename(target) + '.' + process.pid + '.tmp');
		let fh = null;
		try {
			fh = await fsp.open(tmp, 'w', mode);
			await fh.writeFile(data, { encoding: 'utf8' });
			await fh.sync();
			await fh.close();
			fh = null;
			try {
				await fsp.rename(tmp, target);
			} catch (e) {
				if (e?.code !== 'EBUSY') {
					throw e;
				}
				// The file is a mount point of its own, as a file bind
				// mounted into a container is, and cannot be replaced.
				// It is written over in place instead.
				await fsp.unlink(tmp).catch(function() { /*NOTHING*/ });
				await this.#overwrite(target, data);
				return;
			}
		} catch (e) {
			if (fh) {
				await fh.close().catch(function() { /*NOTHING*/ });
			}
			await fsp.unlink(tmp).catch(function() { /*NOTHING*/ });
			throw e;
		}
		try {
			// Makes the rename itself durable where the platform
			// supports it.
			let dh = await fsp.open(path.dirname(target), 'r');
			await dh.sync().catch(function() { /*NOTHING*/ });
			await dh.close();
		} catch (e) {
			/*NOTHING*/
		}
	}

	async #overwrite(target, data) {
		let buf = Buffer.from(data, 'utf8');
		let fh = await fsp.open(target, 'r+');
		try {
			await fh.write(buf, 0, buf.length, 0);
			await fh.truncate(buf.length);
			await fh.sync();
		} finally {
			await fh.close();
		}
	}

	// Starts writing the file whenever the database changes. Write
	// failures are reported as error events.
	watch() {
		if (this.#listeners) {
			return;
		}
		let cb = function() { this.schedule(); }.bind(this);
		this.#listeners = [];
		for (let event of [ 'add', 'update', 'remove', 'flush', 'adddomain', 'removedomain', 'updatedomain' ]) {
			this.#db.on(event, cb);
			this.#listeners.push([ event, cb ]);
		}
	}

	// Notes that the database has changed. The file is written at
	// once if the previous write is old enough, and otherwise when the
	// write interval has passed since it.
	schedule() {
		this.#dirty = true;
		if (this.#timer !== null) {
			return;
		}
		let wait = Math.max(0, (this.#lastWrite + this.#intervalMs) - Date.now());
		this.#timer = setTimeout(function() {
			this.#timer = null;
			if (this.#dirty) {
				this.write().catch(function(e) { this.emit('error', e); }.bind(this));
			}
		}.bind(this), wait);
	}

	// Writes pending changes, if any, and waits for a write that is
	// under way.
	async flush() {
		if (this.#timer !== null) {
			clearTimeout(this.#timer);
			this.#timer = null;
		}
		if (this.#dirty) {
			await this.write();
		} else if (this.#writing) {
			await this.#writing;
		}
	}

	// Stops following the database. Pending changes are not written;
	// call flush() first to keep them.
	close() {
		if (this.#timer !== null) {
			clearTimeout(this.#timer);
			this.#timer = null;
		}
		for (let [ event, cb ] of (this.#listeners ?? [])) {
			this.#db.off(event, cb);
		}
		this.#listeners = null;
	}

}

ConfigStore.ConfigError = ConfigError;

module.exports = ConfigStore;
