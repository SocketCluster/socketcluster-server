/**
 * Module dependencies.
 */

const http = require('http');

/**
 * Expose AGServer constructor.
 *
 * @api public
 */

module.exports.AGServer = require('./server');

/**
 * Expose AGServerSocket constructor.
 *
 * @api public
 */

module.exports.AGServerSocket = require('./serversocket');

/**
 * Expose AGRequest constructor.
 *
 * @api public
 */

module.exports.AGRequest = require('ag-request');

/**
 * Creates an http.Server exclusively used for WS upgrades.
 *
 * @param {Number} port
 * @param {Function} callback
 * @param {Object} options
 * @return {AGServer} websocket cluster server
 * @api public
 */

module.exports.listen = function (port, options, fn) {
  if (typeof options === 'function') {
    fn = options;
    options = {};
  }

  let server = http.createServer((req, res) => {
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
 * @return {AGServer} websocket cluster server
 * @api public
 */

module.exports.attach = function (server, options) {
  if (options == null) {
    options = {};
  }
  options.httpServer = server;
  let socketClusterServer = new module.exports.AGServer(options);
  return socketClusterServer;
};
