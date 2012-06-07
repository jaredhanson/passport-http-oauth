/**
 * Module dependencies.
 */
var TokenStrategy = require('./strategies/token');


/**
 * Strategy version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.TokenStrategy = TokenStrategy;
