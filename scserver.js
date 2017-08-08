var SCSocket = require('./scsocket');
var AuthEngine = require('sc-auth').AuthEngine;
var formatter = require('sc-formatter');
var EventEmitter = require('events').EventEmitter;
var base64id = require('base64id');
var async = require('async');
var url = require('url');
var crypto = require('crypto');
var uuid = require('uuid');
var SCSimpleBroker = require('sc-simple-broker').SCSimpleBroker;

var scErrors = require('sc-errors');
var AuthTokenExpiredError = scErrors.AuthTokenExpiredError;
var AuthTokenInvalidError = scErrors.AuthTokenInvalidError;
var AuthTokenNotBeforeError = scErrors.AuthTokenNotBeforeError;
var AuthTokenError = scErrors.AuthTokenError;
var SilentMiddlewareBlockedError = scErrors.SilentMiddlewareBlockedError;
var InvalidOptionsError = scErrors.InvalidOptionsError;
var InvalidActionError = scErrors.InvalidActionError;
var BrokerError = scErrors.BrokerError;
var ServerProtocolError = scErrors.ServerProtocolError;


var SCServer = function (options) {
  var self = this;

  EventEmitter.call(this);

  var opts = {
    brokerEngine: new SCSimpleBroker(),
    wsEngine: 'uws',
    allowClientPublish: true,
    ackTimeout: 10000,
    handshakeTimeout: 10000,
    pingTimeout: 20000,
    pingInterval: 8000,
    origins: '*:*',
    appName: uuid.v4(),
    path: '/socketcluster/',
    authDefaultExpiry: 86400,
    authSignAsync: false,
    authVerifyAsync: true,
    middlewareEmitWarnings: true
  };

  for (var i in options) {
    if (options.hasOwnProperty(i)) {
      opts[i] = options[i];
    }
  }

  this.options = opts;

  this.MIDDLEWARE_HANDSHAKE = 'handshake';
  this.MIDDLEWARE_EMIT = 'emit';
  this.MIDDLEWARE_SUBSCRIBE = 'subscribe';
  this.MIDDLEWARE_PUBLISH_IN = 'publishIn';
  this.MIDDLEWARE_PUBLISH_OUT = 'publishOut';
  this.MIDDLEWARE_AUTHENTICATE = 'authenticate';

  // Deprecated
  this.MIDDLEWARE_PUBLISH = this.MIDDLEWARE_PUBLISH_IN;

  this._subscribeEvent = '#subscribe';
  this._publishEvent = '#publish';

  this._middleware = {};
  this._middleware[this.MIDDLEWARE_HANDSHAKE] = [];
  this._middleware[this.MIDDLEWARE_EMIT] = [];
  this._middleware[this.MIDDLEWARE_SUBSCRIBE] = [];
  this._middleware[this.MIDDLEWARE_PUBLISH_IN] = [];
  this._middleware[this.MIDDLEWARE_PUBLISH_OUT] = [];
  this._middleware[this.MIDDLEWARE_AUTHENTICATE] = [];

  this.origins = opts.origins;
  this._allowAllOrigins = this.origins.indexOf('*:*') != -1;

  this.ackTimeout = opts.ackTimeout;
  this.handshakeTimeout = opts.handshakeTimeout;
  this.pingInterval = opts.pingInterval;
  this.pingTimeout = opts.pingTimeout;
  this.allowClientPublish = opts.allowClientPublish;
  this.perMessageDeflate = opts.perMessageDeflate;
  this.httpServer = opts.httpServer;
  this.socketChannelLimit = opts.socketChannelLimit;

  this.brokerEngine = opts.brokerEngine;
  this.appName = opts.appName || '';
  this.middlewareEmitWarnings = opts.middlewareEmitWarnings;
  this._path = opts.path;
  this.isReady = false;

  this.brokerEngine.once('ready', function () {
    self.isReady = true;
    EventEmitter.prototype.emit.call(self, 'ready');
  });

  var wsEngine = require(opts.wsEngine);
  if (!wsEngine || !wsEngine.Server) {
    throw new InvalidOptionsError('The wsEngine option must be a path or module name which points ' +
      'to a valid WebSocket engine module with a compatible interface');
  }
  var WSServer = wsEngine.Server;

  if (opts.authPrivateKey != null || opts.authPublicKey != null) {
    if (opts.authPrivateKey == null) {
      throw new InvalidOptionsError('The authPrivateKey option must be specified if authPublicKey is specified');
    } else if (opts.authPublicKey == null) {
      throw new InvalidOptionsError('The authPublicKey option must be specified if authPrivateKey is specified');
    }
    this.signatureKey = opts.authPrivateKey;
    this.verificationKey = opts.authPublicKey;
  } else {
    if (opts.authKey == null) {
      opts.authKey = crypto.randomBytes(32).toString('hex');
    }
    this.signatureKey = opts.authKey;
    this.verificationKey = opts.authKey;
  }

  this.authVerifyAsync = opts.authVerifyAsync;
  this.authSignAsync = opts.authSignAsync;

  this.defaultVerificationOptions = {
    async: this.authVerifyAsync
  };
  this.defaultSignatureOptions = {
    expiresIn: opts.authDefaultExpiry,
    async: this.authSignAsync
  };

  if (opts.authAlgorithm != null) {
    this.defaultVerificationOptions.algorithms = [opts.authAlgorithm];
    this.defaultSignatureOptions.algorithm = opts.authAlgorithm;
  }

  if (opts.authEngine) {
    this.auth = opts.authEngine;
  } else {
    // Default authentication engine
    this.auth = new AuthEngine();
  }

  if (opts.codecEngine) {
    this.codec = opts.codecEngine;
  } else {
    // Default codec engine
    this.codec = formatter;
  }

  this.clients = {};
  this.clientsCount = 0;

  this.exchange = this.global = this.brokerEngine.exchange();

  this.wsServer = new WSServer({
    server: this.httpServer,
    path: this._path,
    clientTracking: false,
    perMessageDeflate: this.perMessageDeflate,
    handleProtocols: opts.handleProtocols,
    verifyClient: this.verifyHandshake.bind(this)
  });

  this.wsServer.on('error', this._handleServerError.bind(this));
  this.wsServer.on('connection', this._handleSocketConnection.bind(this));
};

SCServer.prototype = Object.create(EventEmitter.prototype);

SCServer.prototype.setAuthEngine = function (authEngine) {
  this.auth = authEngine;
};

SCServer.prototype.setCodecEngine = function (codecEngine) {
  this.codec = codecEngine;
};

SCServer.prototype._handleServerError = function (error) {
  if (typeof error == 'string') {
    error = new ServerProtocolError(error);
  }
  this.emit('error', error);
};

SCServer.prototype._handleSocketError = function (error) {
  // We don't want to crash the entire worker on socket error
  // so we emit it as a warning instead.
  this.emit('warning', error);
};

SCServer.prototype._handleHandshakeTimeout = function (scSocket) {
  scSocket.disconnect(4005);
};

SCServer.prototype._subscribeSocket = function (socket, channelOptions, callback) {
  var self = this;

  if (channelOptions instanceof Array) {
    var tasks = [];
    for (var i in channelOptions) {
      if (channelOptions.hasOwnProperty(i)) {
        (function (singleChannelOptions) {
          tasks.push(function (cb) {
            self._subscribeSocketToSingleChannel(socket, singleChannelOptions, cb);
          });
        })(channelOptions[i]);
      }
    }
    async.waterfall(tasks, function (err) {
      callback && callback(err);
    });
  } else {
    this._subscribeSocketToSingleChannel(socket, channelOptions, callback);
  }
};

SCServer.prototype._subscribeSocketToSingleChannel = function (socket, channelOptions, callback) {
  var self = this;
  var channelName = channelOptions.channel;

  if (this.socketChannelLimit && socket.channelSubscriptionsCount >= this.socketChannelLimit) {
    callback && callback('Socket ' + socket.id + ' tried to exceed the channel subscription limit of ' +
      this.socketChannelLimit);
  } else {
    if (socket.channelSubscriptionsCount == null) {
      socket.channelSubscriptionsCount = 0;
    }
    if (socket.channelSubscriptions[channelName] == null) {
      socket.channelSubscriptions[channelName] = true;
      socket.channelSubscriptionsCount++;
    }

    this.brokerEngine.subscribeSocket(socket, channelName, function (err) {
      if (err) {
        delete socket.channelSubscriptions[channelName];
        socket.channelSubscriptionsCount--;
      } else {
        socket.emit('subscribe', channelName, channelOptions);
        self.emit('subscription', socket, channelName, channelOptions);
      }
      callback && callback(err);
    });
  }
};

SCServer.prototype._unsubscribeSocket = function (socket, channels, callback) {
  var self = this;

  if (channels == null) {
    channels = [];
    for (var channel in socket.channelSubscriptions) {
      if (socket.channelSubscriptions.hasOwnProperty(channel)) {
        channels.push(channel);
      }
    }
  }
  if (channels instanceof Array) {
    var tasks = [];
    var len = channels.length;
    for (var i = 0; i < len; i++) {
      (function (channel) {
        tasks.push(function (cb) {
          self._unsubscribeSocketFromSingleChannel(socket, channel, cb);
        });
      })(channels[i]);
    }
    async.waterfall(tasks, function (err) {
      callback && callback(err);
    });
  } else {
    this._unsubscribeSocketFromSingleChannel(socket, channels, callback);
  }
};

SCServer.prototype._unsubscribeSocketFromSingleChannel = function (socket, channel, callback) {
  var self = this;

  delete socket.channelSubscriptions[channel];
  if (socket.channelSubscriptionsCount != null) {
    socket.channelSubscriptionsCount--;
  }

  this.brokerEngine.unsubscribeSocket(socket, channel, function (err) {
    socket.emit('unsubscribe', channel);
    self.emit('unsubscription', socket, channel);
    callback && callback(err);
  });
};

SCServer.prototype._processTokenError = function (err) {
  var authError = null;
  var isBadToken = true;

  if (err) {
    if (err.name == 'TokenExpiredError') {
      authError = new AuthTokenExpiredError(err.message, err.expiredAt);
    } else if (err.name == 'JsonWebTokenError') {
      authError = new AuthTokenInvalidError(err.message);
    } else if (err.name == 'NotBeforeError') {
      authError = new AuthTokenNotBeforeError(err.message, err.date);
      // In this case, the token is good; it's just not active yet.
      isBadToken = false;
    } else {
      authError = new AuthTokenError(err.message);
    }
  }

  return {
    authError: authError,
    isBadToken: isBadToken
  };
};

SCServer.prototype._emitBadAuthTokenError = function (scSocket, error, signedAuthToken) {
  var badAuthStatus = {
    authError: error,
    signedAuthToken: signedAuthToken
  };
  scSocket.emit('badAuthToken', badAuthStatus);
  this.emit('badSocketAuthToken', scSocket, badAuthStatus);
};

SCServer.prototype._processAuthToken = function (scSocket, signedAuthToken, callback) {
  var self = this;

  this.auth.verifyToken(signedAuthToken, this.verificationKey, this.defaultVerificationOptions, function (err, authToken) {
    if (authToken) {
      scSocket.signedAuthToken = signedAuthToken;
      scSocket.authToken = authToken;
      scSocket.authState = scSocket.AUTHENTICATED;
    } else {
      scSocket.signedAuthToken = null;
      scSocket.authToken = null;
      scSocket.authState = scSocket.UNAUTHENTICATED;
    }

    // If the socket is authenticated, pass it through the MIDDLEWARE_AUTHENTICATE middleware.
    // If the token is bad, we will tell the client to remove it.
    // If there is an error but the token is good, then we will send back a 'quiet' error instead
    // (as part of the status object only).
    if (scSocket.authToken) {
      self._passThroughAuthenticateMiddleware({
        socket: scSocket,
        signedAuthToken: scSocket.signedAuthToken,
        authToken: scSocket.authToken
      }, function (middlewareError, isBadToken) {
        if (middlewareError) {
          scSocket.authToken = null;
          scSocket.authState = scSocket.UNAUTHENTICATED;
          if (isBadToken) {
            self._emitBadAuthTokenError(scSocket, middlewareError, signedAuthToken);
          }
        }
        // If an error is passed back from the authenticate middleware, it will be treated as a
        // server warning and not a socket error.
        callback(middlewareError, isBadToken || false);
      });
    } else {
      var errorData = self._processTokenError(err);

      // If the error is related to the JWT being badly formatted, then we will
      // treat the error as a socket error.
      if (err && signedAuthToken != null) {
        scSocket.emit('error', errorData.authError);
        if (errorData.isBadToken) {
          self._emitBadAuthTokenError(scSocket, errorData.authError, signedAuthToken);
        }
      }
      callback(errorData.authError, errorData.isBadToken);
    }
  });
};

SCServer.prototype._handleSocketConnection = function (wsSocket, upgradeReq) {
  var self = this;

  if (this.options.wsEngine == 'ws') {
    // Normalize ws module to match uws module.
    wsSocket.upgradeReq = upgradeReq;
  }

  var id = this.generateId();

  var scSocket = new SCSocket(id, this, wsSocket);
  scSocket.on('error', function (err) {
    self._handleSocketError(err);
  });

  // Emit event to signal that a socket handshake has been initiated.
  // The _handshake event is for internal use (including third-party plugins)
  this.emit('_handshake', scSocket);
  this.emit('handshake', scSocket);

  scSocket.on('#authenticate', function (signedAuthToken, respond) {
    self._processAuthToken(scSocket, signedAuthToken, function (err, isBadToken) {
      if (err) {
        if (isBadToken) {
          scSocket.deauthenticate();
        }
      } else {
        scSocket.emit('authenticate', scSocket.authToken);
        self.emit('authentication', scSocket, scSocket.authToken);
      }
      var authStatus = {
        isAuthenticated: !!scSocket.authToken,
        authError: scErrors.dehydrateError(err)
      };
      if (err && isBadToken) {
        respond(err, authStatus);
      } else {
        respond(null, authStatus);
      }
    });
  });

  scSocket.on('#removeAuthToken', function () {
    var oldToken = scSocket.authToken;
    scSocket.authToken = null;
    scSocket.authState = scSocket.UNAUTHENTICATED;
    scSocket.emit('deauthenticate', oldToken);
    self.emit('deauthentication', scSocket, oldToken);
  });

  scSocket.on('#subscribe', function (channelOptions, res) {
    if (!channelOptions) {
      channelOptions = {};
    } else if (typeof channelOptions == 'string') {
      channelOptions = {
        channel: channelOptions
      };
    }
    self._subscribeSocket(scSocket, channelOptions, function (err) {
      if (err) {
        var error = new BrokerError('Failed to subscribe socket to channel - ' + err);
        res(error);
        scSocket.emit('error', error);
      } else {
        res();
      }
    });
  });

  scSocket.on('#unsubscribe', function (channel, res) {
    self._unsubscribeSocket(scSocket, channel, function (err) {
      if (err) {
        var error = new BrokerError('Failed to unsubscribe socket from channel - ' + err);
        res(error);
        scSocket.emit('error', error);
      } else {
        res();
      }
    });
  });

  scSocket.once('_disconnect', function () {
    clearTimeout(scSocket._handshakeTimeoutRef);

    scSocket.off('#handshake');
    scSocket.off('#authenticate');
    scSocket.off('#removeAuthToken');
    scSocket.off('#subscribe');
    scSocket.off('#unsubscribe');
    scSocket.off('authenticate');
    scSocket.off('deauthenticate');

    var isClientFullyConnected = !!self.clients[id];

    if (isClientFullyConnected) {
      delete self.clients[id];
      self.clientsCount--;
    }

    self._unsubscribeSocket(scSocket, null, function (err) {
      if (err) {
        scSocket.emit('error', new BrokerError('Failed to unsubscribe socket from all channels - ' + err));
      } else if (isClientFullyConnected) {
        self.emit('_disconnection', scSocket);
        self.emit('disconnection', scSocket);
      }
    });
  });

  scSocket._handshakeTimeoutRef = setTimeout(this._handleHandshakeTimeout.bind(this, scSocket), this.handshakeTimeout);
  scSocket.once('#handshake', function (data, respond) {
    if (!data) {
      data = {};
    }
    var signedAuthToken = data.authToken || null;
    clearTimeout(scSocket._handshakeTimeoutRef);

    self._processAuthToken(scSocket, signedAuthToken, function (err, isBadToken) {
      var status = {
        id: scSocket.id,
        pingTimeout: self.pingTimeout
      };

      if (err) {
        if (signedAuthToken != null) {
          // Because the token is optional as part of the handshake, we don't count
          // it as an error if the token wasn't provided.
          status.authError = scErrors.dehydrateError(err);

          if (isBadToken) {
            scSocket.deauthenticate();
          }
        }
      }
      status.isAuthenticated = !!scSocket.authToken;

      self.clients[id] = scSocket;
      self.clientsCount++;

      scSocket.state = scSocket.OPEN;
      scSocket.exchange = scSocket.global = self.exchange;

      self.emit('_connection', scSocket);
      self.emit('connection', scSocket);

      if (status.isAuthenticated) {
        scSocket.emit('authenticate', scSocket.authToken);
        self.emit('authentication', scSocket, scSocket.authToken);
      }
      // Treat authentication failure as a 'soft' error
      respond(null, status);
    });
  });
};

SCServer.prototype.close = function () {
  this.isReady = false;
  this.wsServer.close.apply(this.wsServer, arguments);
};

SCServer.prototype.getPath = function () {
  return this._path;
};

SCServer.prototype.generateId = function () {
  return base64id.generateId();
};

SCServer.prototype.addMiddleware = function (type, middleware) {
  this._middleware[type].push(middleware);
};

SCServer.prototype.removeMiddleware = function (type, middleware) {
  var middlewareFunctions = this._middleware[type];

  this._middleware[type] = middlewareFunctions.filter(function (fn) {
    return fn != middleware;
  });
};

SCServer.prototype.verifyHandshake = function (info, cb) {
  var self = this;

  var req = info.req;
  var origin = info.origin;
  if (origin == 'null' || origin == null) {
    origin = '*';
  }
  var ok = false;

  if (this._allowAllOrigins) {
    ok = true;
  } else {
    try {
      var parts = url.parse(origin);
      parts.port = parts.port || 80;
      ok = ~this.origins.indexOf(parts.hostname + ':' + parts.port) ||
        ~this.origins.indexOf(parts.hostname + ':*') ||
        ~this.origins.indexOf('*:' + parts.port);
    } catch (e) {}
  }

  if (ok) {
    var handshakeMiddleware = this._middleware[this.MIDDLEWARE_HANDSHAKE];
    if (handshakeMiddleware.length) {
      var callbackInvoked = false;
      async.applyEachSeries(handshakeMiddleware, req, function (err) {
        if (callbackInvoked) {
          self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_HANDSHAKE + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true) {
              err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_HANDSHAKE + ' middleware', self.MIDDLEWARE_HANDSHAKE);
            } else if (self.middlewareEmitWarnings) {
              self.emit('warning', err);
            }
            cb(false, 401, err);
          } else {
            cb(true);
          }
        }
      });
    } else {
      cb(true);
    }
  } else {
    var err = new ServerProtocolError('Failed to authorize socket handshake - Invalid origin: ' + origin);
    this.emit('warning', err);
    cb(false, 403, err);
  }
};

SCServer.prototype._isPrivateTransmittedEvent = function (event) {
  return typeof event == 'string' && event.indexOf('#') == 0;
};

SCServer.prototype.verifyInboundEvent = function (socket, eventName, eventData, cb) {
  var request = {
    socket: socket,
    event: eventName,
    data: eventData
  };

  var token = socket.getAuthToken();
  if (this.isAuthTokenExpired(token)) {
    request.authTokenExpiredError = new AuthTokenExpiredError('The socket auth token has expired', token.exp);

    socket.deauthenticate();
  }

  this._passThroughMiddleware(request, cb);
};

SCServer.prototype.isAuthTokenExpired = function (token) {
  if (token && token.exp != null) {
    var currentTime = Date.now();
    var expiryMilliseconds = token.exp * 1000;
    return currentTime > expiryMilliseconds;
  }
  return false;
};

SCServer.prototype._passThroughMiddleware = function (options, cb) {
  var self = this;

  var callbackInvoked = false;

  var request = {
    socket: options.socket
  };

  if (options.authTokenExpiredError != null) {
    request.authTokenExpiredError = options.authTokenExpiredError;
  }

  var event = options.event;

  if (this._isPrivateTransmittedEvent(event)) {
    if (event == this._subscribeEvent) {
      var eventData = options.data || {};
      request.channel = eventData.channel;
      request.waitForAuth = eventData.waitForAuth;
      request.data = eventData.data;

      if (request.waitForAuth && request.authTokenExpiredError) {
        // If the channel has the waitForAuth flag set, then we will handle the expiry quietly
        // and we won't pass this request through the subscribe middleware.
        cb(request.authTokenExpiredError, eventData);
      } else {
        async.applyEachSeries(this._middleware[this.MIDDLEWARE_SUBSCRIBE], request,
          function (err) {
            if (callbackInvoked) {
              self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_SUBSCRIBE + ' middleware was already invoked'));
            } else {
              callbackInvoked = true;
              if (err) {
                if (err === true) {
                  err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_SUBSCRIBE + ' middleware', self.MIDDLEWARE_SUBSCRIBE);
                } else if (self.middlewareEmitWarnings) {
                  self.emit('warning', err);
                }
              }
              if (request.data !== undefined) {
                eventData.data = request.data;
              }
              cb(err, eventData);
            }
          }
        );
      }
    } else if (event == this._publishEvent) {
      if (this.allowClientPublish) {
        var eventData = options.data || {};
        request.channel = eventData.channel;
        request.data = eventData.data;

        async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_IN], request,
          function (err) {
            if (callbackInvoked) {
              self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_PUBLISH_IN + ' middleware was already invoked'));
            } else {
              callbackInvoked = true;
              if (request.data !== undefined) {
                eventData.data = request.data;
              }
              if (err) {
                if (err === true) {
                  err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_PUBLISH_IN + ' middleware', self.MIDDLEWARE_PUBLISH_IN);
                } else if (self.middlewareEmitWarnings) {
                  self.emit('warning', err);
                }
                cb(err, eventData, request.ackData);
              } else {
                self.exchange.publish(request.channel, request.data, function (err) {
                  if (err) {
                    err = new BrokerError(err);
                    self.emit('warning', err);
                  }
                  cb(err, eventData, request.ackData);
                });
              }
            }
          }
        );
      } else {
        var noPublishError = new InvalidActionError('Client publish feature is disabled');
        self.emit('warning', noPublishError);
        cb(noPublishError, options.data);
      }
    } else {
      // Do not allow blocking other reserved events or it could interfere with SC behaviour
      cb(null, options.data);
    }
  } else {
    request.event = event;
    request.data = options.data;

    async.applyEachSeries(this._middleware[this.MIDDLEWARE_EMIT], request,
      function (err) {
        if (callbackInvoked) {
          self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_EMIT + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true) {
              err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_EMIT + ' middleware', self.MIDDLEWARE_EMIT);
            } else if (self.middlewareEmitWarnings) {
              self.emit('warning', err);
            }
          }
          cb(err, request.data);
        }
      }
    );
  }
};

SCServer.prototype._passThroughAuthenticateMiddleware = function (options, cb) {
  var self = this;
  var callbackInvoked = false;

  var request = {
    socket: options.socket,
    authToken: options.authToken
  };

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_AUTHENTICATE], request,
    function (err, results) {
      if (callbackInvoked) {
        self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_AUTHENTICATE + ' middleware was already invoked'));
      } else {
        var isBadToken = false;
        if (results.length) {
          isBadToken = results[results.length - 1] || false;
        }
        callbackInvoked = true;
        if (err) {
          if (err === true) {
            err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_AUTHENTICATE + ' middleware', self.MIDDLEWARE_AUTHENTICATE);
          } else if (self.middlewareEmitWarnings) {
            self.emit('warning', err);
          }
        }
        cb(err, isBadToken);
      }
    }
  );
};

SCServer.prototype.verifyOutboundEvent = function (socket, eventName, eventData, options, cb) {
  var self = this;

  var callbackInvoked = false;

  if (eventName == this._publishEvent) {
    var request = {
      socket: socket,
      channel: eventData.channel,
      data: eventData.data
    };
    async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_OUT], request,
      function (err) {
        if (callbackInvoked) {
          self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_PUBLISH_OUT + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (request.data !== undefined) {
            eventData.data = request.data;
          }
          if (err) {
            if (err === true) {
              err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_PUBLISH_OUT + ' middleware', self.MIDDLEWARE_PUBLISH_OUT);
            } else if (self.middlewareEmitWarnings) {
              self.emit('warning', err);
            }
            cb(err, eventData);
          } else {
            if (options && request.useCache) {
              options.useCache = true;
            }
            cb(null, eventData);
          }
        }
      }
    );
  } else {
    cb(null, eventData);
  }
};

module.exports = SCServer;
