var SCServerSocket = require('./scserversocket');
var AuthEngine = require('sc-auth').AuthEngine;
var formatter = require('sc-formatter');
var EventEmitter = require('events').EventEmitter;
var Emitter = require('component-emitter');
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
var InvalidArgumentsError = scErrors.InvalidArgumentsError;
var InvalidOptionsError = scErrors.InvalidOptionsError;
var InvalidActionError = scErrors.InvalidActionError;
var BrokerError = scErrors.BrokerError;
var ServerProtocolError = scErrors.ServerProtocolError;


var SCServer = function (options) {
  var self = this;

  EventEmitter.call(this);

  var opts = {
    brokerEngine: new SCSimpleBroker(),
    wsEngine: 'ws',
    wsEngineServerOptions: {},
    maxPayload: null,
    allowClientPublish: true,
    ackTimeout: 10000,
    handshakeTimeout: 10000,
    pingTimeout: 20000,
    pingTimeoutDisabled: false,
    pingInterval: 8000,
    origins: '*:*',
    appName: uuid.v4(),
    path: '/socketcluster/',
    authDefaultExpiry: 86400,
    authSignAsync: false,
    authVerifyAsync: true,
    pubSubBatchDuration: null,
    middlewareEmitWarnings: true
  };

  this.options = Object.assign(opts, options);

  this.MIDDLEWARE_HANDSHAKE_WS = 'handshakeWS';
  this.MIDDLEWARE_HANDSHAKE_SC = 'handshakeSC';
  this.MIDDLEWARE_EMIT = 'emit';
  this.MIDDLEWARE_SUBSCRIBE = 'subscribe';
  this.MIDDLEWARE_PUBLISH_IN = 'publishIn';
  this.MIDDLEWARE_PUBLISH_OUT = 'publishOut';
  this.MIDDLEWARE_AUTHENTICATE = 'authenticate';

  // Deprecated
  this.MIDDLEWARE_PUBLISH = this.MIDDLEWARE_PUBLISH_IN;

  this._middleware = {};
  this._middleware[this.MIDDLEWARE_HANDSHAKE_WS] = [];
  this._middleware[this.MIDDLEWARE_HANDSHAKE_SC] = [];
  this._middleware[this.MIDDLEWARE_EMIT] = [];
  this._middleware[this.MIDDLEWARE_SUBSCRIBE] = [];
  this._middleware[this.MIDDLEWARE_PUBLISH_IN] = [];
  this._middleware[this.MIDDLEWARE_PUBLISH_OUT] = [];
  this._middleware[this.MIDDLEWARE_AUTHENTICATE] = [];

  this.origins = opts.origins;
  this._allowAllOrigins = this.origins.indexOf('*:*') !== -1;

  this.ackTimeout = opts.ackTimeout;
  this.handshakeTimeout = opts.handshakeTimeout;
  this.pingInterval = opts.pingInterval;
  this.pingTimeout = opts.pingTimeout;
  this.pingTimeoutDisabled = opts.pingTimeoutDisabled;
  this.allowClientPublish = opts.allowClientPublish;
  this.perMessageDeflate = opts.perMessageDeflate;
  this.httpServer = opts.httpServer;
  this.socketChannelLimit = opts.socketChannelLimit;

  this.brokerEngine = opts.brokerEngine;
  this.appName = opts.appName || '';
  this.middlewareEmitWarnings = opts.middlewareEmitWarnings;

  // Make sure there is always a leading and a trailing slash in the WS path.
  this._path = opts.path.replace(/\/?$/, '/').replace(/^\/?/, '/');
  this.isReady = false;

  this.brokerEngine.once('ready', () => {
    this.isReady = true;
    this.emit('ready');
  });

  var wsEngine = typeof opts.wsEngine === 'string' ? require(opts.wsEngine) : opts.wsEngine;
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
  if (opts.authVerifyAlgorithms != null) {
    this.defaultVerificationOptions.algorithms = opts.authVerifyAlgorithms;
  } else if (opts.authAlgorithm != null) {
    this.defaultVerificationOptions.algorithms = [opts.authAlgorithm];
  }

  this.defaultSignatureOptions = {
    expiresIn: opts.authDefaultExpiry,
    async: this.authSignAsync
  };
  if (opts.authAlgorithm != null) {
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

  this.pendingClients = {};
  this.pendingClientsCount = 0;

  this.exchange = this.brokerEngine.exchange();

  var wsServerOptions = opts.wsEngineServerOptions || {};
  wsServerOptions.server = this.httpServer;
  wsServerOptions.verifyClient = this.verifyHandshake.bind(this);

  if (wsServerOptions.path == null && this._path != null) {
    wsServerOptions.path = this._path;
  }
  if (wsServerOptions.perMessageDeflate == null && this.perMessageDeflate != null) {
    wsServerOptions.perMessageDeflate = this.perMessageDeflate;
  }
  if (wsServerOptions.handleProtocols == null && opts.handleProtocols != null) {
    wsServerOptions.handleProtocols = opts.handleProtocols;
  }
  if (wsServerOptions.maxPayload == null && opts.maxPayload != null) {
    wsServerOptions.maxPayload = opts.maxPayload;
  }
  if (wsServerOptions.clientTracking == null) {
    wsServerOptions.clientTracking = false;
  }

  this.wsServer = new WSServer(wsServerOptions);

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
  if (typeof error === 'string') {
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
  if (!channelOptions) {
    callback && callback('Socket ' + socket.id + ' provided a malformated channel payload');
    return;
  }

  if (this.socketChannelLimit && socket.channelSubscriptionsCount >= this.socketChannelLimit) {
    callback && callback('Socket ' + socket.id + ' tried to exceed the channel subscription limit of ' +
      this.socketChannelLimit);
    return;
  }

  var channelName = channelOptions.channel;

  if (typeof channelName !== 'string') {
    callback && callback('Socket ' + socket.id + ' provided an invalid channel name');
    return;
  }

  if (socket.channelSubscriptionsCount == null) {
    socket.channelSubscriptionsCount = 0;
  }
  if (socket.channelSubscriptions[channelName] == null) {
    socket.channelSubscriptions[channelName] = true;
    socket.channelSubscriptionsCount++;
  }

  this.brokerEngine.subscribeSocket(socket, channelName)
  .then(() => {
    return null;
  })
  .catch((err) => {
    return err;
  })
  .then((err) => {
    if (err) {
      delete socket.channelSubscriptions[channelName];
      socket.channelSubscriptionsCount--;
    } else {
      socket.emit('subscribe', channelName, channelOptions);
      this.emit('subscription', socket, channelName, channelOptions);
    }
    callback && callback(err);
  });
};

SCServer.prototype._unsubscribeSocketFromAllChannels = function (socket) {
  Object.keys(socket.channelSubscriptions).forEach((channelName) => {
    this._unsubscribeSocket(socket, channelName);
  });
};

SCServer.prototype._unsubscribeSocket = function (socket, channel) {
  if (typeof channel !== 'string') {
    throw new InvalidActionError('Socket ' + socket.id + ' tried to unsubscribe from an invalid channel name');
  }
  if (!socket.channelSubscriptions[channel]) {
    throw new InvalidActionError('Socket ' + socket.id + ' tried to unsubscribe from a channel which it is not subscribed to');
  }

  delete socket.channelSubscriptions[channel];
  if (socket.channelSubscriptionsCount != null) {
    socket.channelSubscriptionsCount--;
  }

  this.brokerEngine.unsubscribeSocket(socket, channel);

  socket.emit('unsubscribe', channel);
  this.emit('unsubscription', socket, channel);
};

SCServer.prototype._processTokenError = function (err) {
  var authError = null;
  var isBadToken = true;

  if (err) {
    if (err.name === 'TokenExpiredError') {
      authError = new AuthTokenExpiredError(err.message, err.expiredAt);
    } else if (err.name === 'JsonWebTokenError') {
      authError = new AuthTokenInvalidError(err.message);
    } else if (err.name === 'NotBeforeError') {
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
  var verificationOptions = Object.assign({socket: scSocket}, this.defaultVerificationOptions);

  var handleVerifyTokenResult = (result) => {
    var err = result.error;
    var token = result.token;

    var oldState = scSocket.authState;
    if (token) {
      scSocket.signedAuthToken = signedAuthToken;
      scSocket.authToken = token;
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
      this._passThroughAuthenticateMiddleware({
        socket: scSocket,
        signedAuthToken: scSocket.signedAuthToken,
        authToken: scSocket.authToken
      }, (middlewareError, isBadToken) => {
        if (middlewareError) {
          scSocket.authToken = null;
          scSocket.authState = scSocket.UNAUTHENTICATED;
          if (isBadToken) {
            this._emitBadAuthTokenError(scSocket, middlewareError, signedAuthToken);
          }
        }
        // If an error is passed back from the authenticate middleware, it will be treated as a
        // server warning and not a socket error.
        callback(middlewareError, isBadToken || false, oldState);
      });
    } else {
      var errorData = this._processTokenError(err);

      // If the error is related to the JWT being badly formatted, then we will
      // treat the error as a socket error.
      if (err && signedAuthToken != null) {
        scSocket.emit('error', errorData.authError);
        if (errorData.isBadToken) {
          this._emitBadAuthTokenError(scSocket, errorData.authError, signedAuthToken);
        }
      }
      callback(errorData.authError, errorData.isBadToken, oldState);
    }
  };

  var verifyTokenResult;
  var verifyTokenError;

  try {
    verifyTokenResult = this.auth.verifyToken(signedAuthToken, this.verificationKey, verificationOptions);
  } catch (err) {
    verifyTokenError = err;
  }

  if (verifyTokenResult instanceof Promise) {
    verifyTokenResult
    .then((token) => {
      return {token: token};
    })
    .catch((err) => {
      return {error: err};
    })
    .then(handleVerifyTokenResult);
  } else {
    var result = {
      token: verifyTokenResult,
      error: verifyTokenError
    };
    handleVerifyTokenResult(result);
  }
};

SCServer.prototype._handleSocketConnection = function (wsSocket, upgradeReq) {
  if (this.options.wsEngine === 'ws') {
    // Normalize ws module to match sc-uws module.
    wsSocket.upgradeReq = upgradeReq;
  }

  var id = this.generateId();

  var scSocket = new SCServerSocket(id, this, wsSocket);
  scSocket.exchange = this.exchange;

  scSocket.on('error', (err) => {
    this._handleSocketError(err);
  });

  this.pendingClients[id] = scSocket;
  this.pendingClientsCount++;

  scSocket.on('#authenticate', (signedAuthToken, respond) => {
    this._processAuthToken(scSocket, signedAuthToken, (err, isBadToken, oldState) => {
      if (err) {
        if (isBadToken) {
          scSocket.deauthenticate();
        }
      } else {
        scSocket.triggerAuthenticationEvents(oldState);
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

  scSocket.on('#removeAuthToken', () => {
    scSocket.deauthenticateSelf();
  });

  scSocket.on('#subscribe', (channelOptions, res) => {
    if (!channelOptions) {
      channelOptions = {};
    } else if (typeof channelOptions === 'string') {
      channelOptions = {
        channel: channelOptions
      };
    }
    // This is an invalid state; it means the client tried to subscribe before
    // having completed the handshake.
    if (scSocket.state === scSocket.OPEN) {
      this._subscribeSocket(scSocket, channelOptions, (err) => {
        if (err) {
          var error = new BrokerError('Failed to subscribe socket to the ' + channelOptions.channel + ' channel - ' + err);
          res(error);
          scSocket.emit('error', error);
        } else {
          if (channelOptions.batch) {
            res(undefined, undefined, {batch: true});
          } else {
            res();
          }
        }
      });
    } else {
      var error = new InvalidActionError('Cannot subscribe socket to a channel before it has completed the handshake');
      res(error);
      this.emit('warning', error);
    }
  });

  scSocket.on('#unsubscribe', (channel, res) => {
    var error;
    try {
      this._unsubscribeSocket(scSocket, channel);
    } catch (err) {
      error = new BrokerError('Failed to unsubscribe socket from the ' + channel + ' channel - ' + err.message);
    }
    if (error) {
      res(error);
      scSocket.emit('error', error);
    } else {
      res();
    }
  });

  var cleanupSocket = (type, code, data) => {
    clearTimeout(scSocket._handshakeTimeoutRef);

    scSocket.off('#handshake');
    scSocket.off('#authenticate');
    scSocket.off('#removeAuthToken');
    scSocket.off('#subscribe');
    scSocket.off('#unsubscribe');
    scSocket.off('authenticate');
    scSocket.off('authStateChange');
    scSocket.off('deauthenticate');
    scSocket.off('_disconnect');
    scSocket.off('_connectAbort');

    var isClientFullyConnected = !!this.clients[id];

    if (isClientFullyConnected) {
      delete this.clients[id];
      this.clientsCount--;
    }

    var isClientPending = !!this.pendingClients[id];
    if (isClientPending) {
      delete this.pendingClients[id];
      this.pendingClientsCount--;
    }

    this._unsubscribeSocketFromAllChannels(scSocket);

    if (type === 'disconnect') {
      this.emit('_disconnection', scSocket, code, data);
      this.emit('disconnection', scSocket, code, data);
    } else if (type === 'abort') {
      this.emit('_connectionAbort', scSocket, code, data);
      this.emit('connectionAbort', scSocket, code, data);
    }
    this.emit('_closure', scSocket, code, data);
    this.emit('closure', scSocket, code, data);
  };

  scSocket.once('_disconnect', cleanupSocket.bind(scSocket, 'disconnect'));
  scSocket.once('_connectAbort', cleanupSocket.bind(scSocket, 'abort'));

  scSocket._handshakeTimeoutRef = setTimeout(this._handleHandshakeTimeout.bind(this, scSocket), this.handshakeTimeout);
  scSocket.once('#handshake', (data, respond) => {
    if (!data) {
      data = {};
    }
    var signedAuthToken = data.authToken || null;
    clearTimeout(scSocket._handshakeTimeoutRef);

    this._passThroughHandshakeSCMiddleware({
      socket: scSocket
    }, (err, statusCode) => {
      if (err) {
        if (err.statusCode == null) {
          err.statusCode = statusCode;
        }
        respond(err);
        scSocket.disconnect(err.statusCode);
        return;
      }
      this._processAuthToken(scSocket, signedAuthToken, (err, isBadToken, oldState) => {
        if (scSocket.state === scSocket.CLOSED) {
          return;
        }

        var clientSocketStatus = {
          id: scSocket.id,
          pingTimeout: this.pingTimeout
        };
        var serverSocketStatus = {
          id: scSocket.id,
          pingTimeout: this.pingTimeout
        };

        if (err) {
          if (signedAuthToken != null) {
            // Because the token is optional as part of the handshake, we don't count
            // it as an error if the token wasn't provided.
            clientSocketStatus.authError = scErrors.dehydrateError(err);
            serverSocketStatus.authError = err;

            if (isBadToken) {
              scSocket.deauthenticate();
            }
          }
        }
        clientSocketStatus.isAuthenticated = !!scSocket.authToken;
        serverSocketStatus.isAuthenticated = clientSocketStatus.isAuthenticated;

        if (this.pendingClients[id]) {
          delete this.pendingClients[id];
          this.pendingClientsCount--;
        }
        this.clients[id] = scSocket;
        this.clientsCount++;

        scSocket.state = scSocket.OPEN;

        scSocket.emit('connect', serverSocketStatus);
        scSocket.emit('_connect', serverSocketStatus);

        this.emit('_connection', scSocket, serverSocketStatus);
        this.emit('connection', scSocket, serverSocketStatus);

        if (clientSocketStatus.isAuthenticated) {
          scSocket.triggerAuthenticationEvents(oldState);
        }
        // Treat authentication failure as a 'soft' error
        respond(null, clientSocketStatus);
      });
    });
  });

  // Emit event to signal that a socket handshake has been initiated.
  // The _handshake event is for internal use (including third-party plugins)
  this.emit('_handshake', scSocket);
  this.emit('handshake', scSocket);
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
  if (!this._middleware[type]) {
    throw new InvalidArgumentsError(`Middleware type "${type}" is not supported`);
    // Read more: https://socketcluster.io/#!/docs/middleware-and-authorization
  }
  this._middleware[type].push(middleware);
};

SCServer.prototype.removeMiddleware = function (type, middleware) {
  var middlewareFunctions = this._middleware[type];

  this._middleware[type] = middlewareFunctions.filter((fn) => {
    return fn !== middleware;
  });
};

SCServer.prototype.verifyHandshake = function (info, cb) {
  var req = info.req;
  var origin = info.origin;
  if (origin === 'null' || origin == null) {
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
    var handshakeMiddleware = this._middleware[this.MIDDLEWARE_HANDSHAKE_WS];
    if (handshakeMiddleware.length) {
      var callbackInvoked = false;
      async.applyEachSeries(handshakeMiddleware, req, (err) => {
        if (callbackInvoked) {
          this.emit('warning', new InvalidActionError('Callback for ' + this.MIDDLEWARE_HANDSHAKE_WS + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + this.MIDDLEWARE_HANDSHAKE_WS + ' middleware', this.MIDDLEWARE_HANDSHAKE_WS);
            } else if (this.middlewareEmitWarnings) {
              this.emit('warning', err);
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
  return typeof event === 'string' && event.indexOf('#') === 0;
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
  var callbackInvoked = false;

  var request = {
    socket: options.socket
  };

  if (options.authTokenExpiredError != null) {
    request.authTokenExpiredError = options.authTokenExpiredError;
  }

  var event = options.event;

  if (this._isPrivateTransmittedEvent(event)) {
    if (event === '#subscribe') {
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
          (err) => {
            if (callbackInvoked) {
              this.emit('warning', new InvalidActionError('Callback for ' + this.MIDDLEWARE_SUBSCRIBE + ' middleware was already invoked'));
            } else {
              callbackInvoked = true;
              if (err) {
                if (err === true || err.silent) {
                  err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + this.MIDDLEWARE_SUBSCRIBE + ' middleware', this.MIDDLEWARE_SUBSCRIBE);
                } else if (this.middlewareEmitWarnings) {
                  this.emit('warning', err);
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
    } else if (event === '#publish') {
      if (this.allowClientPublish) {
        var eventData = options.data || {};
        request.channel = eventData.channel;
        request.data = eventData.data;

        async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_IN], request,
          (err) => {
            if (callbackInvoked) {
              this.emit('warning', new InvalidActionError('Callback for ' + this.MIDDLEWARE_PUBLISH_IN + ' middleware was already invoked'));
            } else {
              callbackInvoked = true;
              if (request.data !== undefined) {
                eventData.data = request.data;
              }
              if (err) {
                if (err === true || err.silent) {
                  err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + this.MIDDLEWARE_PUBLISH_IN + ' middleware', this.MIDDLEWARE_PUBLISH_IN);
                } else if (this.middlewareEmitWarnings) {
                  this.emit('warning', err);
                }
                cb(err, eventData, request.ackData);
              } else {
                if (typeof request.channel !== 'string') {
                  err = new BrokerError('Socket ' + request.socket.id + ' tried to publish to an invalid ' + request.channel + ' channel');
                  this.emit('warning', err);
                  cb(err, eventData, request.ackData);
                  return;
                }
                this.exchange.publish(request.channel, request.data)
                .then(() => {
                  return null;
                })
                .catch((err) => {
                  return err;
                })
                .then((err) => {
                  if (err) {
                    this.emit('warning', err);
                  }
                  cb(err, eventData, request.ackData);
                });
              }
            }
          }
        );
      } else {
        var noPublishError = new InvalidActionError('Client publish feature is disabled');
        this.emit('warning', noPublishError);
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
      (err) => {
        if (callbackInvoked) {
          this.emit('warning', new InvalidActionError('Callback for ' + this.MIDDLEWARE_EMIT + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + this.MIDDLEWARE_EMIT + ' middleware', this.MIDDLEWARE_EMIT);
            } else if (this.middlewareEmitWarnings) {
              this.emit('warning', err);
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
    (err, results) => {
      if (callbackInvoked) {
        self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_AUTHENTICATE + ' middleware was already invoked'));
      } else {
        callbackInvoked = true;
        var isBadToken = false;
        if (results.length) {
          isBadToken = results[results.length - 1] || false;
        }
        if (err) {
          if (err === true || err.silent) {
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

SCServer.prototype._passThroughHandshakeSCMiddleware = function (options, cb) {
  var self = this;
  var callbackInvoked = false;

  var request = {
    socket: options.socket
  };

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_HANDSHAKE_SC], request,
    (err, results) => {
      if (callbackInvoked) {
        self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_HANDSHAKE_SC + ' middleware was already invoked'));
      } else {
        callbackInvoked = true;
        var statusCode;
        if (results.length) {
          statusCode = results[results.length - 1] || 4008;
        } else {
          statusCode = 4008;
        }
        if (err) {
          if (err.statusCode != null) {
            statusCode = err.statusCode;
          }
          if (err === true || err.silent) {
            err = new SilentMiddlewareBlockedError('Action was silently blocked by ' + self.MIDDLEWARE_HANDSHAKE_SC + ' middleware', self.MIDDLEWARE_HANDSHAKE_SC);
          } else if (self.middlewareEmitWarnings) {
            self.emit('warning', err);
          }
        }
        cb(err, statusCode);
      }
    }
  );
};

SCServer.prototype.verifyOutboundEvent = function (socket, eventName, eventData, options, cb) {
  var self = this;

  var callbackInvoked = false;

  if (eventName === '#publish') {
    var request = {
      socket: socket,
      channel: eventData.channel,
      data: eventData.data
    };
    async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_OUT], request,
      (err) => {
        if (callbackInvoked) {
          self.emit('warning', new InvalidActionError('Callback for ' + self.MIDDLEWARE_PUBLISH_OUT + ' middleware was already invoked'));
        } else {
          callbackInvoked = true;
          if (request.data !== undefined) {
            eventData.data = request.data;
          }
          if (err) {
            if (err === true || err.silent) {
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
