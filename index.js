/**
 * Module dependencies.
 */

const http = require('http');

/**
 * Expose SCServer constructor.
 *
 * @api public
 */

module.exports.SCServer = require('./scserver');

/**
 * Expose SCServerSocket constructor.
 *
 * @api public
 */

module.exports.SCServerSocket = require('./scserversocket');

/**
 * Creates an http.Server exclusively used for WS upgrades.
 *
 * @param {Number} port
 * @param {Function} callback
 * @param {Object} options
 * @return {SCServer} websocket cluster server
 * @api public
 */

module.exports.listen = function (port, options, fn) {
  if (typeof options === 'function') {
    fn = options;
    options = {};
  }

  let server = http.createServer(function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });

  let socketClusterServer = module.exports.attach(server, options);
  socketClusterServer.httpServer = server;
  server.listen(port, fn);

  return socketClusterServer;
};

/**
 * Captures upgrade requests for a http.Server.
 *
 * @param {http.Server} server
 * @param {Object} options
 * @return {SCServer} websocket cluster server
 * @api public
 */

module.exports.attach = function (server, options) {
  if (options == null) {
    options = {};
  }
  options.httpServer = server;
  let socketClusterServer = new module.exports.SCServer(options);
  return socketClusterServer;
};
