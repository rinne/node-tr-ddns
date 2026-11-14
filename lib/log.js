'use strict'

const ts = require('./ts');

// Messages have a level, and the ones above the current level are not
// printed. Errors and warnings go to the standard error, the rest to
// the standard output.
const LEVELS = { none: 0, error: 1, warn: 2, info: 3, debug: 4 };

let level = LEVELS.info;

function emit(l, av) {
	if (LEVELS[l] > level) {
		return;
	}
	av.unshift(ts() + ':');
	if (LEVELS[l] <= LEVELS.warn) {
		console.error(...av);
	} else {
		console.log(...av);
	}
}

// log(...) is an informational message, as it has always been.
function log(...av) {
	emit('info', av);
}

log.error = function(...av) { emit('error', av); };
log.warn = function(...av) { emit('warn', av); };
log.info = function(...av) { emit('info', av); };
log.debug = function(...av) { emit('debug', av); };

// Sets the level to one of none, error, warn, info and debug.
log.setLevel = function(name) {
	if (! Object.hasOwn(LEVELS, name)) {
		throw new Error('Invalid log level');
	}
	level = LEVELS[name];
};

log.getLevel = function() {
	return Object.keys(LEVELS).find((k) => (LEVELS[k] === level));
};

// Makes sure that debug messages are printed. A component that is
// created with its debug option set calls this.
log.enableDebug = function() {
	level = LEVELS.debug;
};

log.LEVELS = Object.freeze(Object.keys(LEVELS));

module.exports = log;
