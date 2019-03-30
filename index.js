/**
 * Module dependencies.
 */

var argv = require('minimist')(process.argv.slice(2));
var http = require('http');
var https = require('https');
var fs = require('fs');

/*
*
*  SOCKETCLUSTER_SECURE_COM : force https on the internal stack
*  SOCKETCLUSTER_BROKER_SSL_KEY : ssl key for the broker http server
*  SOCKETCLUSTER_BROKER_SSL_CERT : ssl cert for the broker http server
*
*/

// Should not be necessary as the scc-state is not connecting with ws, but only receive connection
//var SOCKETCLUSTER_SSL_REJECT_UNAUTHORIZED = argv.sslru || process.env.SOCKETCLUSTER_BROKER_SSL_REJECT_UNAUTHORIZED || false;


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
  var httpServer;

  httpServer = http.createServer(function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });

  socketClusterServer = module.exports.attach(httpServer, options);
  socketClusterServer.httpServer = httpServer;
  socketClusterServer.httpServer.listen(port);

  return socketClusterServer;


};

module.exports.startSSL = function(port, key, cert, options) {


  //
  // optionSSL.key = (SOCKETCLUSTER_SSL_KEY !== "false") ?  : void 0;
  // optionSSL.cert = (SOCKETCLUSTER_SSL_CERT !== "false") ? fs.readFileSync(SOCKETCLUSTER_SSL_CERT) : void 0;

  httpServer = https.createServer({
    key : key,
    cert : cert
  }, function (req, res) {
    res.writeHead(501);
    res.end('Not Implemented');
  });


  var socketClusterServer = module.exports.attach(httpServer, options);
  socketClusterServer.httpServer = httpServer;
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
