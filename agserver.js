const AGServerSocket = require('./agserversocket');
const AuthEngine = require('ag-auth');
const formatter = require('sc-formatter');
const base64id = require('base64id');
const url = require('url');
const crypto = require('crypto');
const uuid = require('uuid');
const AGSimpleBroker = require('ag-simple-broker');
const AsyncStreamEmitter = require('async-stream-emitter');
const WritableAsyncIterableStream = require('writable-async-iterable-stream');
const Action = require('./action');

const scErrors = require('sc-errors');
const SilentMiddlewareBlockedError = scErrors.SilentMiddlewareBlockedError;
const InvalidArgumentsError = scErrors.InvalidArgumentsError;
const InvalidOptionsError = scErrors.InvalidOptionsError;
const InvalidActionError = scErrors.InvalidActionError;
const BrokerError = scErrors.BrokerError;
const ServerProtocolError = scErrors.ServerProtocolError;

const HANDSHAKE_REJECTION_STATUS_CODE = 4008;

function AGServer(options) {
  AsyncStreamEmitter.call(this);

  let opts = {
    brokerEngine: new AGSimpleBroker(),
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
    pubSubBatchDuration: null,
    middlewareEmitFailures: true
  };

  this.options = Object.assign(opts, options);

  this._middleware = {};

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
  this.middlewareEmitFailures = opts.middlewareEmitFailures;

  // Make sure there is always a leading and a trailing slash in the WS path.
  this._path = opts.path.replace(/\/?$/, '/').replace(/^\/?/, '/');

  (async () => {
    for await (let {error} of this.brokerEngine.listener('error')) {
      this.emitWarning(error);
    }
  })();

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

  this.defaultVerificationOptions = {};
  if (opts.authVerifyAlgorithms != null) {
    this.defaultVerificationOptions.algorithms = opts.authVerifyAlgorithms;
  } else if (opts.authAlgorithm != null) {
    this.defaultVerificationOptions.algorithms = [opts.authAlgorithm];
  }

  this.defaultSignatureOptions = {
    expiresIn: opts.authDefaultExpiry
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
  this.brokerEngine.setCodecEngine(this.codec);
  this.exchange = this.brokerEngine.exchange();

  this.clients = {};
  this.clientsCount = 0;

  this.pendingClients = {};
  this.pendingClientsCount = 0;

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

AGServer.prototype.SYMBOL_MIDDLEWARE_INBOUND_STREAM = AGServer.SYMBOL_MIDDLEWARE_INBOUND_STREAM = Symbol('inboundStream');
AGServer.prototype.SYMBOL_MIDDLEWARE_OUTBOUND_STREAM = AGServer.SYMBOL_MIDDLEWARE_OUTBOUND_STREAM = Symbol('outboundStream');

AGServer.prototype.MIDDLEWARE_INBOUND = AGServer.MIDDLEWARE_INBOUND = 'inbound';
AGServer.prototype.MIDDLEWARE_OUTBOUND = AGServer.MIDDLEWARE_OUTBOUND = 'outbound';

AGServer.prototype.ACTION_HANDSHAKE_WS = AGServer.ACTION_HANDSHAKE_WS = 'handshakeWS';
AGServer.prototype.ACTION_HANDSHAKE_AG = AGServer.ACTION_HANDSHAKE_AG = 'handshakeAG';

AGServer.prototype.ACTION_TRANSMIT = AGServer.ACTION_TRANSMIT = 'transmit';
AGServer.prototype.ACTION_INVOKE = AGServer.ACTION_INVOKE = 'invoke';
AGServer.prototype.ACTION_SUBSCRIBE = AGServer.ACTION_SUBSCRIBE = 'subscribe';
AGServer.prototype.ACTION_PUBLISH_IN = AGServer.ACTION_PUBLISH_IN = 'publishIn';
AGServer.prototype.ACTION_PUBLISH_OUT = AGServer.ACTION_PUBLISH_OUT = 'publishOut';
AGServer.prototype.ACTION_AUTHENTICATE = AGServer.ACTION_AUTHENTICATE = 'authenticate';

AGServer.prototype.setAuthEngine = function (authEngine) {
  this.auth = authEngine;
};

AGServer.prototype.setCodecEngine = function (codecEngine) {
  this.codec = codecEngine;
  this.brokerEngine.setCodecEngine(codecEngine);
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

AGServer.prototype._handleHandshakeTimeout = function (agSocket) {
  agSocket.disconnect(4005);
};

AGServer.prototype._subscribeSocket = async function (socket, channelName, subscriptionOptions) {
  if (channelName === undefined || !subscriptionOptions) {
    throw new InvalidActionError(`Socket ${socket.id} provided a malformated channel payload`);
  }

  if (this.socketChannelLimit && socket.channelSubscriptionsCount >= this.socketChannelLimit) {
    throw new InvalidActionError(
      `Socket ${socket.id} tried to exceed the channel subscription limit of ${this.socketChannelLimit}`
    );
  }

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
    subscriptionOptions
  });
  this.emit('subscription', {
    socket,
    channel: channelName,
    subscriptionOptions
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

AGServer.prototype._handleSocketConnection = function (wsSocket, upgradeReq) {
  if (!wsSocket.upgradeReq) {
    // Normalize ws modules to match.
    wsSocket.upgradeReq = upgradeReq;
  }

  let socketId = this.generateId();

  let agSocket = new AGServerSocket(socketId, this, wsSocket);
  agSocket.exchange = this.exchange;

  let socketOutboundMiddleware = this._middleware[this.MIDDLEWARE_OUTBOUND];
  if (socketOutboundMiddleware) {
    socketOutboundMiddleware(agSocket._middlewareOutboundStream);
  }

  this.pendingClients[socketId] = agSocket;
  this.pendingClientsCount++;

  let handleSocketAuthenticate = async () => {
    for await (let rpc of agSocket.procedure('#authenticate')) {
      let signedAuthToken = rpc.data;
      let oldAuthState = agSocket.authState;
      try {
        await agSocket._processAuthToken(signedAuthToken);
      } catch (error) {
        if (error.isBadToken) {
          agSocket.deauthenticate();
          rpc.error(error);

          return;
        }

        rpc.end({
          isAuthenticated: !!agSocket.authToken,
          authError: signedAuthToken == null ? null : scErrors.dehydrateError(error)
        });

        return;
      }
      agSocket.triggerAuthenticationEvents(oldAuthState);
      rpc.end({
        isAuthenticated: !!agSocket.authToken,
        authError: null
      });
    }
  };
  handleSocketAuthenticate();

  let handleSocketRemoveAuthToken = async () => {
    for await (let data of agSocket.receiver('#removeAuthToken')) {
      agSocket.deauthenticateSelf();
    }
  };
  handleSocketRemoveAuthToken();

  let handleSocketSubscribe = async () => {
    for await (let rpc of agSocket.procedure('#subscribe')) {
      let subscriptionOptions = Object.assign({}, rpc.data);
      let channelName = subscriptionOptions.channel;
      delete subscriptionOptions.channel;

      (async () => {
        if (agSocket.state === agSocket.OPEN) {
          try {
            await this._subscribeSocket(agSocket, channelName, subscriptionOptions);
          } catch (err) {
            let error = new BrokerError(`Failed to subscribe socket to the ${channelName} channel - ${err}`);
            rpc.error(error);
            agSocket.emitError(error);

            return;
          }
          if (subscriptionOptions.batch) {
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
    for await (let rpc of agSocket.procedure('#unsubscribe')) {
      let channel = rpc.data;
      let error;
      try {
        this._unsubscribeSocket(agSocket, channel);
      } catch (err) {
        error = new BrokerError(
          `Failed to unsubscribe socket from the ${channel} channel - ${err}`
        );
      }
      if (error) {
        rpc.error(error);
        agSocket.emitError(error);
      } else {
        rpc.end();
      }
    }
  };
  handleSocketUnsubscribe();

  let cleanupSocket = (type, code, reason) => {
    clearTimeout(agSocket._handshakeTimeoutRef);

    agSocket.closeProcedure('#handshake');
    agSocket.closeProcedure('#authenticate');
    agSocket.closeProcedure('#subscribe');
    agSocket.closeProcedure('#unsubscribe');
    agSocket.closeReceiver('#removeAuthToken');
    agSocket.closeListener('authenticate');
    agSocket.closeListener('authStateChange');
    agSocket.closeListener('deauthenticate');
    agSocket._middlewareOutboundStream.close();
    agSocket._middlewareInboundStream.close();

    let isClientFullyConnected = !!this.clients[socketId];

    if (isClientFullyConnected) {
      delete this.clients[socketId];
      this.clientsCount--;
    }

    let isClientPending = !!this.pendingClients[socketId];
    if (isClientPending) {
      delete this.pendingClients[socketId];
      this.pendingClientsCount--;
    }

    if (type === 'disconnect') {
      this.emit('disconnection', {
        socket: agSocket,
        code,
        reason
      });
    } else if (type === 'abort') {
      this.emit('connectionAbort', {
        socket: agSocket,
        code,
        reason
      });
    }
    this.emit('closure', {
      socket: agSocket,
      code,
      reason
    });

    this._unsubscribeSocketFromAllChannels(agSocket);
  };

  let handleSocketDisconnect = async () => {
    let event = await agSocket.listener('disconnect').once();
    cleanupSocket('disconnect', event.code, event.data);
  };
  handleSocketDisconnect();

  let handleSocketAbort = async () => {
    let event = await agSocket.listener('connectAbort').once();
    cleanupSocket('abort', event.code, event.data);
  };
  handleSocketAbort();

  agSocket._handshakeTimeoutRef = setTimeout(this._handleHandshakeTimeout.bind(this, agSocket), this.handshakeTimeout);

  let handleSocketHandshake = async () => {
    for await (let rpc of agSocket.procedure('#handshake')) {
      let data = rpc.data || {};
      let signedAuthToken = data.authToken || null;
      clearTimeout(agSocket._handshakeTimeoutRef);

      let action = new Action();
      action.type = this.ACTION_HANDSHAKE_AG;
      action.socket = agSocket;

      try {
        await this._processMiddlewareAction(agSocket._middlewareInboundStream, action);
      } catch (error) {
        if (error.statusCode == null) {
          error.statusCode = HANDSHAKE_REJECTION_STATUS_CODE;
        }
        rpc.error(error);
        agSocket.disconnect(error.statusCode);
        return;
      }

      let clientSocketStatus = {
        id: socketId,
        pingTimeout: this.pingTimeout
      };
      let serverSocketStatus = {
        id: socketId,
        pingTimeout: this.pingTimeout
      };

      let oldAuthState = agSocket.authState;
      try {
        await agSocket._processAuthToken(signedAuthToken);
        if (agSocket.state === agSocket.CLOSED) {
          return;
        }
      } catch (error) {
        if (signedAuthToken != null) {
          // Because the token is optional as part of the handshake, we don't count
          // it as an error if the token wasn't provided.
          clientSocketStatus.authError = scErrors.dehydrateError(error);
          serverSocketStatus.authError = error;

          if (error.isBadToken) {
            agSocket.deauthenticate();
          }
        }
      }
      clientSocketStatus.isAuthenticated = !!agSocket.authToken;
      serverSocketStatus.isAuthenticated = clientSocketStatus.isAuthenticated;

      if (this.pendingClients[socketId]) {
        delete this.pendingClients[socketId];
        this.pendingClientsCount--;
      }
      this.clients[socketId] = agSocket;
      this.clientsCount++;

      agSocket.state = agSocket.OPEN;

      if (clientSocketStatus.isAuthenticated) {
        // Needs to be executed after the connection event to allow
        // consumers to be setup from inside the connection loop.
        (async () => {
          await this.listener('connection').once();
          agSocket.triggerAuthenticationEvents(oldAuthState);
        })();
      }

      agSocket.emit('connect', serverSocketStatus);
      this.emit('connection', {socket: agSocket, ...serverSocketStatus});

      // Treat authentication failure as a 'soft' error
      rpc.end(clientSocketStatus);
    }
  };
  handleSocketHandshake();

  // Emit event to signal that a socket handshake has been initiated.
  this.emit('handshake', {socket: agSocket});
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

AGServer.prototype.setMiddleware = function (type, middleware) {
  if (
    type !== this.MIDDLEWARE_INBOUND &&
    type !== this.MIDDLEWARE_OUTBOUND
  ) {
    throw new InvalidArgumentsError(
      `Middleware type "${type}" is not supported`
    );
  }
  if (this._middleware[type]) {
    throw new InvalidActionError(`Middleware type "${type}" has already been set`);
  }
  this._middleware[type] = middleware;
};

AGServer.prototype.removeMiddleware = function (type) {
  delete this._middleware[type];
};

AGServer.prototype.hasMiddleware = function (type) {
  return !!this._middleware[type];
};

AGServer.prototype._processMiddlewareAction = async function (middlewareStream, action, socket) {
  if (!this.hasMiddleware(middlewareStream.type)) {
    return {data: action.data, options: null};
  }
  middlewareStream.write(action);

  let newData;
  let options = null;
  try {
    let result = await action.promise;
    if (result) {
      newData = result.data;
      options = result.options;
    }
  } catch (error) {
    let clientError;
    if (error.silent) {
      clientError = new SilentMiddlewareBlockedError(
        `Action was blocked by ${action.name} middleware`,
        action.name
      );
    } else {
      clientError = error;
    }
    if (this.middlewareEmitFailures) {
      if (socket) {
        socket.emitError(error);
      } else {
        this.emitWarning(error);
      }
    }
    throw clientError;
  }

  if (newData === undefined) {
    newData = action.data;
  }

  return {data: newData, options};
};

AGServer.prototype.verifyHandshake = async function (info, callback) {
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
    let middlewareInboundStream = new WritableAsyncIterableStream();
    middlewareInboundStream.type = this.MIDDLEWARE_INBOUND;
    req[this.SYMBOL_MIDDLEWARE_INBOUND_STREAM] = middlewareInboundStream;

    let serverInboundMiddleware = this._middleware[this.MIDDLEWARE_INBOUND];
    if (serverInboundMiddleware) {
      serverInboundMiddleware(middlewareInboundStream);
    }
    let action = new Action();
    action.type = this.ACTION_HANDSHAKE_WS;
    action.request = req;

    try {
      await this._processMiddlewareAction(middlewareInboundStream, action);
    } catch (error) {
      callback(false, 401, typeof error === 'string' ? error : error.message);
      return;
    }
    callback(true);
    return;
  }
  let error = new ServerProtocolError(
    `Failed to authorize socket handshake - Invalid origin: ${origin}`
  );
  this.emitWarning(error);
  callback(false, 403, error.message);
};

module.exports = AGServer;
