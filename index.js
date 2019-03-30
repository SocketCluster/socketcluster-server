/**
 * Module dependencies.
 */

var argv = require('minimist')(process.argv.slice(2));
var http = require('http');
var https = require('https');
var fs = require('fs');

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


//
module.exports.start = function(port, options) {

  var server = http.createServer(function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });

  var socketClusterServer = module.exports.attach(server, options);
  socketClusterServer.httpServer = server;
  socketClusterServer.httpServer.listen(port);

  return socketClusterServer;


};

module.exports.startSSL = function(port, keyPath, crtPath, options) {

  var server = https.createServer({
    key : fs.readFileSync(keyPath),
    cert : fs.readFileSync(crtPath)
  }, function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });

  var socketClusterServer = module.exports.attach(server, options);
  socketClusterServer.httpServer = server;
  socketClusterServer.httpServer.listen(port);

  return socketClusterServer;


};

module.exports.listen = function (port, options, fn) {
  if (typeof options === 'function') {
    fn = options;
    options = {};
  }

  server = http.createServer(function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });

  var engine = module.exports.attach(server, options);
  engine.httpServer = server;
  server.listen(port, fn);

  return engine;
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
  socketClusterServer = new module.exports.SCServer(options);
  return socketClusterServer;
};
