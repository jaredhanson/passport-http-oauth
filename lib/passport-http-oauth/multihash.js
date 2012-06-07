/**
 * `MultiHash` constructor.
 *
 * @api private
 */
function MultiHash() {
  this._hash = {};
  this.__defineGetter__('length', this._length);
}

/**
 * Test if `key` is set.
 *
 * @param {String} key
 * @return {Boolean} _true_ if set, _false_ otherwise
 * @api private
 */
MultiHash.prototype.has = function(key) {
  return (this._hash[key] !== undefined);
}

/**
 * Number of values set for `key`.
 *
 * @param {String} key
 * @return {Number}
 * @api private
 */
MultiHash.prototype.count = function(key) {
  return this.has(key) ? this._hash[key].length : 0;
}

/**
 * Array of keys.
 *
 * @return {Array}
 * @api private
 */
MultiHash.prototype.keys = function() {
  return Object.keys(this._hash);
}

/**
 * Array of values for `key`.
 *
 * @param {String} key
 * @return {Array}
 * @api private
 */
MultiHash.prototype.values = function(key) {
  return this.has(key) ? this._hash[key] : [];
}

/**
 * Put `value` for `key`.
 *
 * Multi-hashes can contain multiple values for the same key.  Putting a value
 * to a key will add a value, rather than replace an existing value.
 *
 * @param {String} key
 * @param {Mixed} value
 * @api private
 */
MultiHash.prototype.put = function(key, value) {
  if (this.has(key)) {
    this._hash[key].push(value);
  } else {
    this._hash[key] = [ value ];
  }
}

/**
 * Add keys and values of `obj`.
 *
 * @param {Object} obj
 * @param {Mixed} value
 * @api private
 */
MultiHash.prototype.add = function(obj) {
  if (!obj) { return; }
  var self = this;
  Object.keys(obj).forEach(function(key) {
    self.put(key, obj[key]);
  });
}

/**
 * Delete `key`.
 *
 * @param {String} key
 * @api private
 */
MultiHash.prototype.del = function(key) {
  delete this._hash[key];
}

/**
 * Number of keys in the multi-hash.
 *
 * @return {Number}
 * @api private
 */
MultiHash.prototype._length = function() {
  return this.keys().length;
}


/**
 * Expose `MultiHash`.
 */ 
module.exports = MultiHash;
