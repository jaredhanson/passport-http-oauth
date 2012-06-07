/**
 * Module dependencies.
 */
var ConsumerStrategy = require('./strategies/consumer');
var TokenStrategy = require('./strategies/token');


/**
 * Strategy version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.ClientStrategy =
exports.ConsumerStrategy = ConsumerStrategy;
exports.TokenStrategy = TokenStrategy;
