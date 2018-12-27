const AGServerSocket = require('./agserversocket');
const AuthEngine = require('sc-auth').AuthEngine;
const formatter = require('sc-formatter');
const base64id = require('base64id');
const async = require('async');
const url = require('url');
const crypto = require('crypto');
const uuid = require('uuid');
const SCSimpleBroker = require('sc-simple-broker').SCSimpleBroker;
const AsyncStreamEmitter = require('async-stream-emitter');

const scErrors = require('sc-errors');
const AuthTokenExpiredError = scErrors.AuthTokenExpiredError;
const AuthTokenInvalidError = scErrors.AuthTokenInvalidError;
const AuthTokenNotBeforeError = scErrors.AuthTokenNotBeforeError;
const AuthTokenError = scErrors.AuthTokenError;
const SilentMiddlewareBlockedError = scErrors.SilentMiddlewareBlockedError;
const InvalidArgumentsError = scErrors.InvalidArgumentsError;
const InvalidOptionsError = scErrors.InvalidOptionsError;
const InvalidActionError = scErrors.InvalidActionError;
const BrokerError = scErrors.BrokerError;
const ServerProtocolError = scErrors.ServerProtocolError;

function AGServer(options) {
  AsyncStreamEmitter.call(this);

  let opts = {
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
  this.MIDDLEWARE_TRANSMIT = 'transmit';
  this.MIDDLEWARE_INVOKE = 'invoke';
  this.MIDDLEWARE_SUBSCRIBE = 'subscribe';
  this.MIDDLEWARE_PUBLISH_IN = 'publishIn';
  this.MIDDLEWARE_PUBLISH_OUT = 'publishOut';
  this.MIDDLEWARE_AUTHENTICATE = 'authenticate';

  // Deprecated
  this.MIDDLEWARE_PUBLISH = this.MIDDLEWARE_PUBLISH_IN;

  this._middleware = {};
  this._middleware[this.MIDDLEWARE_HANDSHAKE_WS] = [];
  this._middleware[this.MIDDLEWARE_HANDSHAKE_SC] = [];
  this._middleware[this.MIDDLEWARE_TRANSMIT] = [];
  this._middleware[this.MIDDLEWARE_INVOKE] = [];
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

  if (this.brokerEngine.isReady) {
    this.isReady = true;
    this.emit('ready', {});
  } else {
    this.isReady = false;
    (async () => {
      await this.brokerEngine.listener('ready').once();
      this.isReady = true;
      this.emit('ready', {});
    })();
  }

  let wsEngine = typeof opts.wsEngine === 'string' ? require(opts.wsEngine) : opts.wsEngine;
  if (!wsEngine || !wsEngine.Server) {
    throw new InvalidOptionsError(
      'The wsEngine option must be a path or module name which points ' +
      'to a valid WebSocket engine module with a compatible interface'
    );
  }
  let WSServer = wsEngine.Server;

  if (opts.authPrivateKey != null || opts.authPublicKey != null) {
    if (opts.authPrivateKey == null) {
      throw new InvalidOptionsError(
        'The authPrivateKey option must be specified if authPublicKey is specified'
      );
    } else if (opts.authPublicKey == null) {
      throw new InvalidOptionsError(
        'The authPublicKey option must be specified if authPrivateKey is specified'
      );
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

  let wsServerOptions = opts.wsEngineServerOptions || {};
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
}

AGServer.prototype = Object.create(AsyncStreamEmitter.prototype);

AGServer.prototype.setAuthEngine = function (authEngine) {
  this.auth = authEngine;
};

AGServer.prototype.setCodecEngine = function (codecEngine) {
  this.codec = codecEngine;
};

AGServer.prototype.emitError = function (error) {
  this.emit('error', {error});
};

AGServer.prototype.emitWarning = function (warning) {
  this.emit('warning', {warning});
};

AGServer.prototype._handleServerError = function (error) {
  if (typeof error === 'string') {
    error = new ServerProtocolError(error);
  }
  this.emitError(error);
};

AGServer.prototype._handleSocketErrors = async function (socket) {
  // A socket error will show up as a warning on the server.
  for await (let event of socket.listener('error')) {
    this.emitWarning(event.error);
  }
};

AGServer.prototype._handleHandshakeTimeout = function (scSocket) {
  scSocket.disconnect(4005);
};

AGServer.prototype._subscribeSocket = async function (socket, channelOptions) {
  if (!channelOptions) {
    throw new InvalidActionError(`Socket ${socket.id} provided a malformated channel payload`);
  }

  if (this.socketChannelLimit && socket.channelSubscriptionsCount >= this.socketChannelLimit) {
    throw new InvalidActionError(
      `Socket ${socket.id} tried to exceed the channel subscription limit of ${this.socketChannelLimit}`
    );
  }

  let channelName = channelOptions.channel;

  if (typeof channelName !== 'string') {
    throw new InvalidActionError(`Socket ${socket.id} provided an invalid channel name`);
  }

  if (socket.channelSubscriptionsCount == null) {
    socket.channelSubscriptionsCount = 0;
  }
  if (socket.channelSubscriptions[channelName] == null) {
    socket.channelSubscriptions[channelName] = true;
    socket.channelSubscriptionsCount++;
  }

  try {
    await this.brokerEngine.subscribeSocket(socket, channelName);
  } catch (err) {
    delete socket.channelSubscriptions[channelName];
    socket.channelSubscriptionsCount--;
    throw err;
  }
  socket.emit('subscribe', {
    channel: channelName,
    subscribeOptions: channelOptions
  });
  this.emit('subscription', {
    socket,
    channel: channelName,
    subscribeOptions: channelOptions
  });
};

AGServer.prototype._unsubscribeSocketFromAllChannels = function (socket) {
  Object.keys(socket.channelSubscriptions).forEach((channelName) => {
    this._unsubscribeSocket(socket, channelName);
  });
};

AGServer.prototype._unsubscribeSocket = function (socket, channel) {
  if (typeof channel !== 'string') {
    throw new InvalidActionError(
      `Socket ${socket.id} tried to unsubscribe from an invalid channel name`
    );
  }
  if (!socket.channelSubscriptions[channel]) {
    throw new InvalidActionError(
      `Socket ${socket.id} tried to unsubscribe from a channel which it is not subscribed to`
    );
  }

  delete socket.channelSubscriptions[channel];
  if (socket.channelSubscriptionsCount != null) {
    socket.channelSubscriptionsCount--;
  }

  this.brokerEngine.unsubscribeSocket(socket, channel);

  socket.emit('unsubscribe', {channel});
  this.emit('unsubscription', {socket, channel});
};

AGServer.prototype._processTokenError = function (err) {
  let authError = null;
  let isBadToken = true;

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

AGServer.prototype._emitBadAuthTokenError = function (scSocket, error, signedAuthToken) {
  let badAuthStatus = {
    authError: error,
    signedAuthToken: signedAuthToken
  };
  scSocket.emit('badAuthToken', {
    authError: error,
    signedAuthToken: signedAuthToken
  });
  this.emit('badSocketAuthToken', {
    socket: scSocket,
    authError: error,
    signedAuthToken: signedAuthToken
  });
};

AGServer.prototype._processAuthToken = function (scSocket, signedAuthToken, callback) {
  let verificationOptions = Object.assign({socket: scSocket}, this.defaultVerificationOptions);

  let handleVerifyTokenResult = (result) => {
    let err = result.error;
    let token = result.token;

    let oldAuthState = scSocket.authState;
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
        callback(middlewareError, isBadToken || false, oldAuthState);
      });
    } else {
      let errorData = this._processTokenError(err);

      // If the error is related to the JWT being badly formatted, then we will
      // treat the error as a socket error.
      if (err && signedAuthToken != null) {
        scSocket.emitError(errorData.authError);
        if (errorData.isBadToken) {
          this._emitBadAuthTokenError(scSocket, errorData.authError, signedAuthToken);
        }
      }
      callback(errorData.authError, errorData.isBadToken, oldAuthState);
    }
  };

  let verifyTokenResult;
  let verifyTokenError;

  try {
    verifyTokenResult = this.auth.verifyToken(signedAuthToken, this.verificationKey, verificationOptions);
  } catch (err) {
    verifyTokenError = err;
  }

  if (verifyTokenResult instanceof Promise) {
    (async () => {
      let result = {};
      try {
        result.token = await verifyTokenResult;
      } catch (err) {
        result.error = err;
      }
      handleVerifyTokenResult(result);
    })();
  } else {
    let result = {
      token: verifyTokenResult,
      error: verifyTokenError
    };
    handleVerifyTokenResult(result);
  }
};

AGServer.prototype._handleSocketConnection = function (wsSocket, upgradeReq) {
  if (!wsSocket.upgradeReq) {
    // Normalize ws modules to match.
    wsSocket.upgradeReq = upgradeReq;
  }

  let id = this.generateId();

  let scSocket = new AGServerSocket(id, this, wsSocket);
  scSocket.exchange = this.exchange;

  this._handleSocketErrors(scSocket);

  this.pendingClients[id] = scSocket;
  this.pendingClientsCount++;

  let handleSocketAuthenticate = async () => {
    for await (let rpc of scSocket.procedure('#authenticate')) {
      let signedAuthToken = rpc.data;

      this._processAuthToken(scSocket, signedAuthToken, (err, isBadToken, oldAuthState) => {
        if (err) {
          if (isBadToken) {
            scSocket.deauthenticate();
          }
        } else {
          scSocket.triggerAuthenticationEvents(oldAuthState);
        }
        if (err && isBadToken) {
          rpc.error(err);
        } else {
          let authStatus = {
            isAuthenticated: !!scSocket.authToken,
            authError: scErrors.dehydrateError(err)
          };
          rpc.end(authStatus);
        }
      });
    }
  };
  handleSocketAuthenticate();

  let handleSocketRemoveAuthToken = async () => {
    for await (let data of scSocket.receiver('#removeAuthToken')) {
      scSocket.deauthenticateSelf();
    }
  };
  handleSocketRemoveAuthToken();

  let handleSocketSubscribe = async () => {
    for await (let rpc of scSocket.procedure('#subscribe')) {
      let channelOptions = rpc.data;

      if (!channelOptions) {
        channelOptions = {};
      } else if (typeof channelOptions === 'string') {
        channelOptions = {
          channel: channelOptions
        };
      }

      (async () => {
        if (scSocket.state === scSocket.OPEN) {
          try {
            await this._subscribeSocket(scSocket, channelOptions);
          } catch (err) {
            let error = new BrokerError(`Failed to subscribe socket to the ${channelOptions.channel} channel - ${err}`);
            rpc.error(error);
            scSocket.emitError(error);
            return;
          }
          if (channelOptions.batch) {
            rpc.end(undefined, {batch: true});
            return;
          }
          rpc.end();
          return;
        }
        // This is an invalid state; it means the client tried to subscribe before
        // having completed the handshake.
        let error = new InvalidActionError('Cannot subscribe socket to a channel before it has completed the handshake');
        rpc.error(error);
        this.emitWarning(error);
      })();
    }
  };
  handleSocketSubscribe();

  let handleSocketUnsubscribe = async () => {
    for await (let rpc of scSocket.procedure('#unsubscribe')) {
      let channel = rpc.data;
      let error;
      try {
        this._unsubscribeSocket(scSocket, channel);
      } catch (err) {
        error = new BrokerError(
          `Failed to unsubscribe socket from the ${channel} channel - ${err}`
        );
      }
      if (error) {
        rpc.error(error);
        scSocket.emitError(error);
      } else {
        rpc.end();
      }
    }
  };
  handleSocketUnsubscribe();

  let cleanupSocket = (type, code, reason) => {
    clearTimeout(scSocket._handshakeTimeoutRef);

    scSocket.closeProcedure('#handshake');
    scSocket.closeProcedure('#authenticate');
    scSocket.closeProcedure('#subscribe');
    scSocket.closeProcedure('#unsubscribe');
    scSocket.closeReceiver('#removeAuthToken');
    scSocket.closeListener('authenticate');
    scSocket.closeListener('authStateChange');
    scSocket.closeListener('deauthenticate');

    let isClientFullyConnected = !!this.clients[id];

    if (isClientFullyConnected) {
      delete this.clients[id];
      this.clientsCount--;
    }

    let isClientPending = !!this.pendingClients[id];
    if (isClientPending) {
      delete this.pendingClients[id];
      this.pendingClientsCount--;
    }

    if (type === 'disconnect') {
      this.emit('disconnection', {
        socket: scSocket,
        code,
        reason
      });
    } else if (type === 'abort') {
      this.emit('connectionAbort', {
        socket: scSocket,
        code,
        reason
      });
    }
    this.emit('closure', {
      socket: scSocket,
      code,
      reason
    });

    this._unsubscribeSocketFromAllChannels(scSocket);
  };

  let handleSocketDisconnect = async () => {
    let event = await scSocket.listener('disconnect').once();
    cleanupSocket('disconnect', event.code, event.data);
  };
  handleSocketDisconnect();

  let handleSocketAbort = async () => {
    let event = await scSocket.listener('connectAbort').once();
    cleanupSocket('abort', event.code, event.data);
  };
  handleSocketAbort();

  scSocket._handshakeTimeoutRef = setTimeout(this._handleHandshakeTimeout.bind(this, scSocket), this.handshakeTimeout);

  let handleSocketHandshake = async () => {
    for await (let rpc of scSocket.procedure('#handshake')) {
      let data = rpc.data || {};
      let signedAuthToken = data.authToken || null;
      clearTimeout(scSocket._handshakeTimeoutRef);

      this._passThroughHandshakeSCMiddleware({
        socket: scSocket
      }, (err, statusCode) => {
        if (err) {
          if (err.statusCode == null) {
            err.statusCode = statusCode;
          }
          rpc.error(err);
          scSocket.disconnect(err.statusCode);
          return;
        }
        this._processAuthToken(scSocket, signedAuthToken, (err, isBadToken, oldAuthState) => {
          if (scSocket.state === scSocket.CLOSED) {
            return;
          }

          let clientSocketStatus = {
            id: scSocket.id,
            pingTimeout: this.pingTimeout
          };
          let serverSocketStatus = {
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

          if (clientSocketStatus.isAuthenticated) {
            // Needs to be executed after the connection event to allow
            // consumers to be setup from inside the connection loop.
            (async () => {
              await this.listener('connection').once();
              scSocket.triggerAuthenticationEvents(oldAuthState);
            })();
          }

          scSocket.emit('connect', serverSocketStatus);
          this.emit('connection', {socket: scSocket, ...serverSocketStatus});

          // Treat authentication failure as a 'soft' error
          rpc.end(clientSocketStatus);
        });
      });
    }
  };
  handleSocketHandshake();

  // Emit event to signal that a socket handshake has been initiated.
  this.emit('handshake', {socket: scSocket});
};

AGServer.prototype.close = function () {
  this.isReady = false;
  return new Promise((resolve, reject) => {
    this.wsServer.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
};

AGServer.prototype.getPath = function () {
  return this._path;
};

AGServer.prototype.generateId = function () {
  return base64id.generateId();
};

AGServer.prototype.addMiddleware = function (type, middleware) {
  if (!this._middleware[type]) {
    throw new InvalidArgumentsError(`Middleware type "${type}" is not supported`);
    // Read more: https://socketcluster.io/#!/docs/middleware-and-authorization
  }
  this._middleware[type].push(middleware);
};

AGServer.prototype.removeMiddleware = function (type, middleware) {
  let middlewareFunctions = this._middleware[type];

  this._middleware[type] = middlewareFunctions.filter((fn) => {
    return fn !== middleware;
  });
};

AGServer.prototype.verifyHandshake = function (info, callback) {
  let req = info.req;
  let origin = info.origin;
  if (origin === 'null' || origin == null) {
    origin = '*';
  }
  let ok = false;

  if (this._allowAllOrigins) {
    ok = true;
  } else {
    try {
      let parts = url.parse(origin);
      parts.port = parts.port || 80;
      ok = ~this.origins.indexOf(parts.hostname + ':' + parts.port) ||
        ~this.origins.indexOf(parts.hostname + ':*') ||
        ~this.origins.indexOf('*:' + parts.port);
    } catch (e) {}
  }

  if (ok) {
    let handshakeMiddleware = this._middleware[this.MIDDLEWARE_HANDSHAKE_WS];
    if (handshakeMiddleware.length) {
      let callbackInvoked = false;
      async.applyEachSeries(handshakeMiddleware, req, (err) => {
        if (callbackInvoked) {
          this.emitWarning(
            new InvalidActionError(
              `Callback for ${this.MIDDLEWARE_HANDSHAKE_WS} middleware was already invoked`
            )
          );
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError(
                `Action was silently blocked by ${this.MIDDLEWARE_HANDSHAKE_WS} middleware`,
                this.MIDDLEWARE_HANDSHAKE_WS
              );
            } else if (this.middlewareEmitWarnings) {
              this.emitWarning(err);
            }
            callback(false, 401, typeof err === 'string' ? err : err.message);
          } else {
            callback(true);
          }
        }
      });
    } else {
      callback(true);
    }
  } else {
    let err = new ServerProtocolError(
      `Failed to authorize socket handshake - Invalid origin: ${origin}`
    );
    this.emitWarning(err);
    callback(false, 403, err.message);
  }
};

AGServer.prototype._isReservedRemoteEvent = function (event) {
  return typeof event === 'string' && event.indexOf('#') === 0;
};

AGServer.prototype.verifyInboundRemoteEvent = function (requestOptions, callback) {
  let socket = requestOptions.socket;
  let token = socket.getAuthToken();
  if (this.isAuthTokenExpired(token)) {
    requestOptions.authTokenExpiredError = new AuthTokenExpiredError(
      'The socket auth token has expired',
      token.exp
    );

    socket.deauthenticate();
  }

  this._passThroughMiddleware(requestOptions, callback);
};

AGServer.prototype.isAuthTokenExpired = function (token) {
  if (token && token.exp != null) {
    let currentTime = Date.now();
    let expiryMilliseconds = token.exp * 1000;
    return currentTime > expiryMilliseconds;
  }
  return false;
};

AGServer.prototype._processPublishAction = function (options, request, callback) {
  let callbackInvoked = false;

  if (this.allowClientPublish) {
    let eventData = options.data || {};
    request.channel = eventData.channel;
    request.data = eventData.data;

    async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_IN], request,
      (err) => {
        if (callbackInvoked) {
          this.emitWarning(
            new InvalidActionError(
              `Callback for ${this.MIDDLEWARE_PUBLISH_IN} middleware was already invoked`
            )
          );
        } else {
          callbackInvoked = true;
          if (request.data !== undefined) {
            eventData.data = request.data;
          }
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError(
                `Action was silently blocked by ${this.MIDDLEWARE_PUBLISH_IN} middleware`,
                this.MIDDLEWARE_PUBLISH_IN
              );
            } else if (this.middlewareEmitWarnings) {
              this.emitWarning(err);
            }
            callback(err, eventData, request.ackData);
          } else {
            if (typeof request.channel !== 'string') {
              err = new BrokerError(
                `Socket ${request.socket.id} tried to publish to an invalid ${request.channel} channel`
              );
              this.emitWarning(err);
              callback(err, eventData, request.ackData);
              return;
            }
            (async () => {
              let error;
              try {
                await this.exchange.publish(request.channel, request.data);
              } catch (err) {
                error = err;
                this.emitWarning(error);
              }
              callback(error, eventData, request.ackData);
            })();
          }
        }
      }
    );
  } else {
    let noPublishError = new InvalidActionError('Client publish feature is disabled');
    this.emitWarning(noPublishError);
    callback(noPublishError);
  }
};

AGServer.prototype._processSubscribeAction = function (options, request, callback) {
  let callbackInvoked = false;

  let eventData = options.data || {};
  request.channel = eventData.channel;
  request.waitForAuth = eventData.waitForAuth;
  request.data = eventData.data;

  if (request.waitForAuth && request.authTokenExpiredError) {
    // If the channel has the waitForAuth flag set, then we will handle the expiry quietly
    // and we won't pass this request through the subscribe middleware.
    callback(request.authTokenExpiredError, eventData);
  } else {
    async.applyEachSeries(this._middleware[this.MIDDLEWARE_SUBSCRIBE], request,
      (err) => {
        if (callbackInvoked) {
          this.emitWarning(
            new InvalidActionError(
              `Callback for ${this.MIDDLEWARE_SUBSCRIBE} middleware was already invoked`
            )
          );
        } else {
          callbackInvoked = true;
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError(
                `Action was silently blocked by ${this.MIDDLEWARE_SUBSCRIBE} middleware`,
                this.MIDDLEWARE_SUBSCRIBE
              );
            } else if (this.middlewareEmitWarnings) {
              this.emitWarning(err);
            }
          }
          if (request.data !== undefined) {
            eventData.data = request.data;
          }
          callback(err, eventData);
        }
      }
    );
  }
};

AGServer.prototype._processTransmitAction = function (options, request, callback) {
  let callbackInvoked = false;

  request.event = options.event;
  request.data = options.data;

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_TRANSMIT], request,
    (err) => {
      if (callbackInvoked) {
        this.emitWarning(
          new InvalidActionError(
            `Callback for ${this.MIDDLEWARE_TRANSMIT} middleware was already invoked`
          )
        );
      } else {
        callbackInvoked = true;
        if (err) {
          if (err === true || err.silent) {
            err = new SilentMiddlewareBlockedError(
              `Action was silently blocked by ${this.MIDDLEWARE_TRANSMIT} middleware`,
              this.MIDDLEWARE_TRANSMIT
            );
          } else if (this.middlewareEmitWarnings) {
            this.emitWarning(err);
          }
        }
        callback(err, request.data);
      }
    }
  );
};

AGServer.prototype._processInvokeAction = function (options, request, callback) {
  let callbackInvoked = false;

  request.event = options.event;
  request.data = options.data;

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_INVOKE], request,
    (err) => {
      if (callbackInvoked) {
        this.emitWarning(
          new InvalidActionError(
            `Callback for ${this.MIDDLEWARE_INVOKE} middleware was already invoked`
          )
        );
      } else {
        callbackInvoked = true;
        if (err) {
          if (err === true || err.silent) {
            err = new SilentMiddlewareBlockedError(
              `Action was silently blocked by ${this.MIDDLEWARE_INVOKE} middleware`,
              this.MIDDLEWARE_INVOKE
            );
          } else if (this.middlewareEmitWarnings) {
            this.emitWarning(err);
          }
        }
        callback(err, request.data);
      }
    }
  );
};

AGServer.prototype._passThroughMiddleware = function (options, callback) {
  let request = {
    socket: options.socket
  };

  if (options.authTokenExpiredError != null) {
    request.authTokenExpiredError = options.authTokenExpiredError;
  }

  let event = options.event;

  if (options.cid == null) {
    // If transmit.
    if (this._isReservedRemoteEvent(event)) {
      if (event === '#publish') {
        this._processPublishAction(options, request, callback);
      } else if (event === '#removeAuthToken') {
        callback(null, options.data);
      } else {
        let error = new InvalidActionError(`The reserved transmitted event ${event} is not supported`);
        callback(error);
      }
    } else {
      this._processTransmitAction(options, request, callback);
    }
  } else {
    // If invoke/RPC.
    if (this._isReservedRemoteEvent(event)) {
      if (event === '#subscribe') {
        this._processSubscribeAction(options, request, callback);
      } else if (event === '#publish') {
        this._processPublishAction(options, request, callback);
      } else if (
        event === '#handshake' ||
        event === '#authenticate' ||
        event === '#unsubscribe'
      ) {
        callback(null, options.data);
      } else {
        let error = new InvalidActionError(`The reserved invoked event ${event} is not supported`);
        callback(error);
      }
    } else {
      this._processInvokeAction(options, request, callback);
    }
  }
};

AGServer.prototype._passThroughAuthenticateMiddleware = function (options, callback) {
  let callbackInvoked = false;

  let request = {
    socket: options.socket,
    authToken: options.authToken
  };

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_AUTHENTICATE], request,
    (err, results) => {
      if (callbackInvoked) {
        this.emitWarning(
          new InvalidActionError(
            `Callback for ${this.MIDDLEWARE_AUTHENTICATE} middleware was already invoked`
          )
        );
      } else {
        callbackInvoked = true;
        let isBadToken = false;
        if (results.length) {
          isBadToken = results[results.length - 1] || false;
        }
        if (err) {
          if (err === true || err.silent) {
            err = new SilentMiddlewareBlockedError(
              `Action was silently blocked by ${this.MIDDLEWARE_AUTHENTICATE} middleware`,
              this.MIDDLEWARE_AUTHENTICATE
            );
          } else if (this.middlewareEmitWarnings) {
            this.emitWarning(err);
          }
        }
        callback(err, isBadToken);
      }
    }
  );
};

AGServer.prototype._passThroughHandshakeSCMiddleware = function (options, callback) {
  let callbackInvoked = false;

  let request = {
    socket: options.socket
  };

  async.applyEachSeries(this._middleware[this.MIDDLEWARE_HANDSHAKE_SC], request,
    (err, results) => {
      if (callbackInvoked) {
        this.emitWarning(
          new InvalidActionError(
            `Callback for ${this.MIDDLEWARE_HANDSHAKE_SC} middleware was already invoked`
          )
        );
      } else {
        callbackInvoked = true;
        let statusCode;
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
            err = new SilentMiddlewareBlockedError(
              `Action was silently blocked by ${this.MIDDLEWARE_HANDSHAKE_SC} middleware`,
              this.MIDDLEWARE_HANDSHAKE_SC
            );
          } else if (this.middlewareEmitWarnings) {
            this.emitWarning(err);
          }
        }
        callback(err, statusCode);
      }
    }
  );
};

AGServer.prototype.verifyOutboundEvent = function (socket, eventName, eventData, options, callback) {
  let callbackInvoked = false;

  if (eventName === '#publish') {
    let request = {
      socket: socket,
      channel: eventData.channel,
      data: eventData.data
    };
    async.applyEachSeries(this._middleware[this.MIDDLEWARE_PUBLISH_OUT], request,
      (err) => {
        if (callbackInvoked) {
          this.emitWarning(
            new InvalidActionError(
              `Callback for ${this.MIDDLEWARE_PUBLISH_OUT} middleware was already invoked`
            )
          );
        } else {
          callbackInvoked = true;
          if (request.data !== undefined) {
            eventData.data = request.data;
          }
          if (err) {
            if (err === true || err.silent) {
              err = new SilentMiddlewareBlockedError(
                `Action was silently blocked by ${this.MIDDLEWARE_PUBLISH_OUT} middleware`,
                this.MIDDLEWARE_PUBLISH_OUT
              );
            } else if (this.middlewareEmitWarnings) {
              this.emitWarning(err);
            }
            callback(err, eventData);
          } else {
            if (options && request.useCache) {
              options.useCache = true;
            }
            callback(null, eventData);
          }
        }
      }
    );
  } else {
    callback(null, eventData);
  }
};

module.exports = AGServer;
