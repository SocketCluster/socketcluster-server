const AGServerSocket = require('./serversocket');
const AuthEngine = require('ag-auth');
const formatter = require('sc-formatter');
const base64id = require('base64id');
const url = require('url');
const crypto = require('crypto');
const AGSimpleBroker = require('ag-simple-broker');
const AsyncStreamEmitter = require('async-stream-emitter');
const WritableConsumableStream = require('writable-consumable-stream');
const AGAction = require('./action');

const scErrors = require('sc-errors');
const SilentMiddlewareBlockedError = scErrors.SilentMiddlewareBlockedError;
const InvalidArgumentsError = scErrors.InvalidArgumentsError;
const InvalidOptionsError = scErrors.InvalidOptionsError;
const InvalidActionError = scErrors.InvalidActionError;
const ServerProtocolError = scErrors.ServerProtocolError;

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
    strictHandshake: true,
    pingTimeout: 20000,
    pingTimeoutDisabled: false,
    pingInterval: 8000,
    origins: '*:*',
    path: '/socketcluster/',
    protocolVersion: 2,
    authDefaultExpiry: 86400,
    batchOnHandshake: false,
    batchOnHandshakeDuration: 400,
    batchInterval: 50,
    middlewareEmitFailures: true,
    socketStreamCleanupMode: 'kill',
    cloneData: false
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
  this.protocolVersion = opts.protocolVersion;
  this.strictHandshake = opts.strictHandshake;

  this.brokerEngine = opts.brokerEngine;
  this.middlewareEmitFailures = opts.middlewareEmitFailures;

  this._path = opts.path;

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

AGServer.prototype.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM = AGServer.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM = Symbol('handshakeStream');

AGServer.prototype.MIDDLEWARE_HANDSHAKE = AGServer.MIDDLEWARE_HANDSHAKE = 'handshake';
AGServer.prototype.MIDDLEWARE_INBOUND_RAW = AGServer.MIDDLEWARE_INBOUND_RAW = 'inboundRaw';
AGServer.prototype.MIDDLEWARE_INBOUND = AGServer.MIDDLEWARE_INBOUND = 'inbound';
AGServer.prototype.MIDDLEWARE_OUTBOUND = AGServer.MIDDLEWARE_OUTBOUND = 'outbound';

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

AGServer.prototype._handleSocketConnection = function (wsSocket, upgradeReq) {
  if (!wsSocket.upgradeReq) {
    // Normalize ws modules to match.
    wsSocket.upgradeReq = upgradeReq;
  }

  let socketId = this.generateId();

  let agSocket = new AGServerSocket(socketId, this, wsSocket, this.protocolVersion);
  agSocket.exchange = this.exchange;

  let inboundRawMiddleware = this._middleware[this.MIDDLEWARE_INBOUND_RAW];
  if (inboundRawMiddleware) {
    inboundRawMiddleware(agSocket.middlewareInboundRawStream);
  }

  let inboundMiddleware = this._middleware[this.MIDDLEWARE_INBOUND];
  if (inboundMiddleware) {
    inboundMiddleware(agSocket.middlewareInboundStream);
  }

  let outboundMiddleware = this._middleware[this.MIDDLEWARE_OUTBOUND];
  if (outboundMiddleware) {
    outboundMiddleware(agSocket.middlewareOutboundStream);
  }

  // Emit event to signal that a socket handshake has been initiated.
  this.emit('handshake', {socket: agSocket});
};

AGServer.prototype.close = function (keepSocketsOpen) {
  this.isReady = false;
  return new Promise((resolve, reject) => {
    this.wsServer.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
    if (!keepSocketsOpen) {
      for (let socket of Object.values(this.clients)) {
        socket.terminate();
      }
    }
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
    type !== this.MIDDLEWARE_HANDSHAKE &&
    type !== this.MIDDLEWARE_INBOUND_RAW &&
    type !== this.MIDDLEWARE_INBOUND &&
    type !== this.MIDDLEWARE_OUTBOUND
  ) {
    throw new InvalidArgumentsError(
      `Middleware ${type} type is not supported`
    );
  }
  if (this._middleware[type]) {
    throw new InvalidActionError(`Middleware ${type} type has already been set`);
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
    if (!error) {
      error = new SilentMiddlewareBlockedError(
        `The ${action.type} AGAction was blocked by ${middlewareStream.type} middleware`,
        middlewareStream.type
      );
      clientError = error;
    } else if (error.silent) {
      clientError = new SilentMiddlewareBlockedError(
        `The ${action.type} AGAction was blocked by ${middlewareStream.type} middleware`,
        middlewareStream.type
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
  if (typeof origin !== 'string' || origin === 'null') {
    origin = '*';
  }
  let ok = false;

  if (this._allowAllOrigins) {
    ok = true;
  } else {
    try {
      let parts = url.parse(origin);
      parts.port = parts.port || (parts.protocol === 'https:' ? 443 : 80);
      ok = ~this.origins.indexOf(parts.hostname + ':' + parts.port) ||
        ~this.origins.indexOf(parts.hostname + ':*') ||
        ~this.origins.indexOf('*:' + parts.port);
    } catch (e) {}
  }

  let middlewareHandshakeStream = new WritableConsumableStream();
  middlewareHandshakeStream.type = this.MIDDLEWARE_HANDSHAKE;

  req[this.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM] = middlewareHandshakeStream;

  let handshakeMiddleware = this._middleware[this.MIDDLEWARE_HANDSHAKE];
  if (handshakeMiddleware) {
    handshakeMiddleware(middlewareHandshakeStream);
  }

  let action = new AGAction();
  action.request = req;
  action.type = AGAction.HANDSHAKE_WS;

  try {
    await this._processMiddlewareAction(middlewareHandshakeStream, action);
  } catch (error) {
    middlewareHandshakeStream.close();
    callback(false, 401, typeof error === 'string' ? error : error.message);
    return;
  }

  if (ok) {
    callback(true);
    return;
  }

  let error = new ServerProtocolError(
    `Failed to authorize socket handshake - Invalid origin: ${origin}`
  );
  this.emitWarning(error);

  middlewareHandshakeStream.close();
  callback(false, 403, error.message);
};

module.exports = AGServer;
