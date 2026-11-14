'use strict'

const ts = require('./ts');

function log(...av) {
	av.unshift(ts() + ':');
	console.log(...av);
}

module.exports = log;
