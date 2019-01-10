const cloneDeep = require('lodash.clonedeep');
const WritableAsyncIterableStream = require('writable-async-iterable-stream');
const StreamDemux = require('stream-demux');
const AsyncStreamEmitter = require('async-stream-emitter');
const Action = require('./action');
const Request = require('./request');

const scErrors = require('sc-errors');
const InvalidArgumentsError = scErrors.InvalidArgumentsError;
const SocketProtocolError = scErrors.SocketProtocolError;
const TimeoutError = scErrors.TimeoutError;
const InvalidActionError = scErrors.InvalidActionError;
const AuthError = scErrors.AuthError;
const AuthTokenExpiredError = scErrors.AuthTokenExpiredError;
const AuthTokenInvalidError = scErrors.AuthTokenInvalidError;
const AuthTokenNotBeforeError = scErrors.AuthTokenNotBeforeError;
const AuthTokenError = scErrors.AuthTokenError;
const SilentMiddlewareBlockedError = scErrors.SilentMiddlewareBlockedError;

function AGServerSocket(id, server, socket) {
  AsyncStreamEmitter.call(this);

  this.id = id;
  this.server = server;
  this.socket = socket;
  this.state = this.CONNECTING;
  this.authState = this.UNAUTHENTICATED;

  this._receiverDemux = new StreamDemux();
  this._procedureDemux = new StreamDemux();

  this.request = this.socket.upgradeReq;

  // TODO 2: Add MIDDLEWARE_INBOUND_RAW for applying middleware on raw messages.
  this._middlewareInboundStream = this.request[this.server.SYMBOL_MIDDLEWARE_INBOUND_STREAM];
  this._middlewareOutboundStream = new WritableAsyncIterableStream();
  this._middlewareOutboundStream.type = this.server.MIDDLEWARE_OUTBOUND;

  if (this.request.connection) {
    this.remoteAddress = this.request.connection.remoteAddress;
    this.remoteFamily = this.request.connection.remoteFamily;
    this.remotePort = this.request.connection.remotePort;
  } else {
    this.remoteAddress = this.request.remoteAddress;
    this.remoteFamily = this.request.remoteFamily;
    this.remotePort = this.request.remotePort;
  }
  if (this.request.forwardedForAddress) {
    this.forwardedForAddress = this.request.forwardedForAddress;
  }

  this._cid = 1;
  this._callbackMap = {};
  this._batchSendList = [];

  this.channelSubscriptions = {};
  this.channelSubscriptionsCount = 0;

  this.socket.on('error', (err) => {
    this.emitError(err);
  });

  this.socket.on('close', (code, data) => {
    this._onClose(code, data);
  });

  if (!this.server.pingTimeoutDisabled) {
    this._pingIntervalTicker = setInterval(this._sendPing.bind(this), this.server.pingInterval);
  }
  this._resetPongTimeout();

  // Receive incoming raw messages
  this.socket.on('message', (message, flags) => {
    this._resetPongTimeout();

    this.emit('message', {message});

    let packet;
    try {
      packet = this.decode(message);
    } catch (err) {
      if (err.name === 'Error') {
        err.name = 'InvalidMessageError';
      }
      this.emitError(err);
      return;
    }

    // If pong
    if (packet === '#2') {
      let token = this.getAuthToken();
      if (this.isAuthTokenExpired(token)) {
        this.deauthenticate();
      }
    } else {
      if (Array.isArray(packet)) {
        let len = packet.length;
        for (let i = 0; i < len; i++) {
          this._processInboundPacket(packet[i], message);
        }
      } else {
        this._processInboundPacket(packet, message);
      }
    }
  });
}

AGServerSocket.prototype = Object.create(AsyncStreamEmitter.prototype);

AGServerSocket.CONNECTING = AGServerSocket.prototype.CONNECTING = 'connecting';
AGServerSocket.OPEN = AGServerSocket.prototype.OPEN = 'open';
AGServerSocket.CLOSED = AGServerSocket.prototype.CLOSED = 'closed';

AGServerSocket.AUTHENTICATED = AGServerSocket.prototype.AUTHENTICATED = 'authenticated';
AGServerSocket.UNAUTHENTICATED = AGServerSocket.prototype.UNAUTHENTICATED = 'unauthenticated';

AGServerSocket.ignoreStatuses = scErrors.socketProtocolIgnoreStatuses;
AGServerSocket.errorStatuses = scErrors.socketProtocolErrorStatuses;

AGServerSocket.prototype.receiver = function (receiverName) {
  return this._receiverDemux.stream(receiverName);
};

AGServerSocket.prototype.closeReceiver = function (receiverName) {
  this._receiverDemux.close(receiverName);
};

AGServerSocket.prototype.procedure = function (procedureName) {
  return this._procedureDemux.stream(procedureName);
};

AGServerSocket.prototype.closeProcedure = function (procedureName) {
  this._procedureDemux.close(procedureName);
};

AGServerSocket.prototype._sendPing = function () {
  if (this.state !== this.CLOSED) {
    this.sendObject('#1');
  }
};

AGServerSocket.prototype._processInboundPacket = async function (packet, message) {
  if (packet && packet.event != null) {
    let eventName = packet.event;
    let isRPC = packet.cid != null;

    if (eventName === '#handshake' || eventName === '#authenticate') {
      // Let AGServer handle these events.
      let request = new Request(this, packet.cid, eventName, packet.data);
      this._procedureDemux.write(eventName, request);

      return;
    }
    if (eventName === '#removeAuthToken') {
      this._receiverDemux.write(eventName, packet.data);

      return;
    }

    let tokenExpiredError = this._processAuthTokenExpiry();

    let action = new Action();
    action.socket = this;

    let isPublish = eventName === '#publish';
    let isSubscribe = eventName === '#subscribe';

    if (isPublish) {
      if (!this.server.allowClientPublish) {
        let error = new InvalidActionError('Client publish feature is disabled');
        this.emitError(error);

        if (isRPC) {
          let request = new Request(this, packet.cid, eventName, packet.data);
          request.error(error);
        }
        return;
      }
      action.type = this.server.ACTION_PUBLISH_IN;
      if (packet.data) {
        action.channel = packet.data.channel;
        action.data = packet.data.data;
      }
    } else if (isSubscribe) {
      action.type = this.server.ACTION_SUBSCRIBE;
      if (packet.data) {
        action.channel = packet.data.channel;
        action.data = packet.data.data;
      }
    } else if (eventName === '#unsubscribe') {
      // Let AGServer handle this event.
      let request = new Request(this, packet.cid, eventName, packet.data);
      this._procedureDemux.write(eventName, request);

      return;
    } else {
      if (isRPC) {
        action.type = this.server.ACTION_INVOKE;
        action.procedure = packet.event;
        if (packet.data !== undefined) {
          action.data = packet.data;
        }
      } else {
        action.type = this.server.ACTION_TRANSMIT;
        action.receiver = packet.event;
        if (packet.data !== undefined) {
          action.data = packet.data;
        }
      }
    }

    let newData;

    if (tokenExpiredError) {
      action.authTokenExpiredError = tokenExpiredError;
    }

    if (isRPC) {
      let request = new Request(this, packet.cid, eventName, packet.data);
      try {
        let {data} = await this.server._processMiddlewareAction(this._middlewareInboundStream, action, this);
        newData = data;
      } catch (error) {
        request.error(error);

        return;
      }

      if (isPublish || isSubscribe) {
        request.data = request.data || {};
        request.data.data = newData;
      } else {
        request.data = newData;
      }
      if (isPublish) {
        let publishPacket = request.data || {};

        if (typeof publishPacket.channel !== 'string') {
          let error = new InvalidActionError(`Socket ${this.id} tried to publish to an invalid "${publishPacket.channel}" channel`);
          this.emitError(error);
          request.error(error);

          return;
        }

        try {
          await this.server.exchange.publish(publishPacket.channel, publishPacket.data);
        } catch (error) {
          this.emitError(error);
          request.error(error);

          return;
        }
        request.end();

        return;
      }

      this._procedureDemux.write(eventName, request);

      return;
    }

    try {
      let {data} = await this.server._processMiddlewareAction(this._middlewareInboundStream, action, this);
      newData = data;
    } catch (error) {

      return;
    }

    this._receiverDemux.write(eventName, newData);

    return;
  }

  if (packet && packet.rid != null) {
    // If incoming message is a response to a previously sent message
    let ret = this._callbackMap[packet.rid];
    if (ret) {
      clearTimeout(ret.timeout);
      delete this._callbackMap[packet.rid];
      let rehydratedError = scErrors.hydrateError(packet.error);
      ret.callback(rehydratedError, packet.data);
    }
    return;
  }
  // The last remaining case is to treat the message as raw
  this.emit('raw', {message});
};

AGServerSocket.prototype._resetPongTimeout = function () {
  if (this.server.pingTimeoutDisabled) {
    return;
  }
  clearTimeout(this._pingTimeoutTicker);
  this._pingTimeoutTicker = setTimeout(() => {
    this._onClose(4001);
    this.socket.close(4001);
  }, this.server.pingTimeout);
};

AGServerSocket.prototype._nextCallId = function () {
  return this._cid++;
};

AGServerSocket.prototype.getState = function () {
  return this.state;
};

AGServerSocket.prototype.getBytesReceived = function () {
  return this.socket.bytesReceived;
};

AGServerSocket.prototype.emitError = function (error) {
  this.emit('error', {error});
  this.server.emitWarning(error);
};

AGServerSocket.prototype._onClose = function (code, reason) {
  clearInterval(this._pingIntervalTicker);
  clearTimeout(this._pingTimeoutTicker);

  if (this.state !== this.CLOSED) {
    let prevState = this.state;
    this.state = this.CLOSED;

    if (prevState === this.CONNECTING) {
      this.emit('connectAbort', {code, reason});
    } else {
      this.emit('disconnect', {code, reason});
    }
    this.emit('close', {code, reason});

    if (!AGServerSocket.ignoreStatuses[code]) {
      let closeMessage;
      if (reason) {
        let reasonString;
        if (typeof reason === 'object') {
          try {
            reasonString = JSON.stringify(reason);
          } catch (error) {
            reasonString = reason.toString();
          }
        } else {
          reasonString = reason;
        }
        closeMessage = `Socket connection closed with status code ${code} and reason: ${reasonString}`;
      } else {
        closeMessage = `Socket connection closed with status code ${code}`;
      }
      let err = new SocketProtocolError(AGServerSocket.errorStatuses[code] || closeMessage, code);
      this.emitError(err);
    }
  }
};

AGServerSocket.prototype.disconnect = function (code, data) {
  code = code || 1000;

  if (typeof code !== 'number') {
    let err = new InvalidArgumentsError('If specified, the code argument must be a number');
    this.emitError(err);
  }

  if (this.state !== this.CLOSED) {
    this._onClose(code, data);
    this.socket.close(code, data);
  }
};

AGServerSocket.prototype.terminate = function () {
  this.socket.terminate();
};

AGServerSocket.prototype.send = function (data, options) {
  this.socket.send(data, options, (err) => {
    if (err) {
      this._onClose(1006, err.toString());
    }
  });
};

AGServerSocket.prototype.decode = function (message) {
  return this.server.codec.decode(message);
};

AGServerSocket.prototype.encode = function (object) {
  return this.server.codec.encode(object);
};

AGServerSocket.prototype.sendObjectBatch = function (object) {
  this._batchSendList.push(object);
  if (this._batchTimeout) {
    return;
  }

  this._batchTimeout = setTimeout(() => {
    delete this._batchTimeout;
    if (this._batchSendList.length) {
      let str;
      try {
        str = this.encode(this._batchSendList);
      } catch (err) {
        this.emitError(err);
      }
      if (str != null) {
        this.send(str);
      }
      this._batchSendList = [];
    }
  }, this.server.options.pubSubBatchDuration || 0);
};

AGServerSocket.prototype.sendObjectSingle = function (object) {
  let str;
  try {
    str = this.encode(object);
  } catch (err) {
    this.emitError(err);
  }
  if (str != null) {
    this.send(str);
  }
};

AGServerSocket.prototype.sendObject = function (object, options) {
  if (options && options.batch) {
    this.sendObjectBatch(object);
  } else {
    this.sendObjectSingle(object);
  }
};

AGServerSocket.prototype.transmit = async function (event, data, options) {
  let newData;
  let useCache = options ? options.useCache : false;
  let packet = {event, data};
  let isPublish = event === '#publish';
  if (isPublish) {
    let action = new Action();
    action.type = this.server.ACTION_PUBLISH_OUT;
    action.socket = this;

    if (data !== undefined) {
      action.channel = data.channel;
      action.data = data.data;
    }
    useCache = !this.server.hasMiddleware(this._middlewareOutboundStream.type);

    try {
      let {data, options} = await this.server._processMiddlewareAction(this._middlewareOutboundStream, action, this);
      newData = data;
      useCache = options == null ? useCache : options.useCache;
    } catch (error) {

      return;
    }
  } else {
    newData = packet.data;
  }

  if (options && useCache && options.stringifiedData != null) {
    // Optimized
    this.send(options.stringifiedData);
  } else {
    let eventObject = {
      event
    };
    if (isPublish) {
      eventObject.data = data || {};
      eventObject.data.data = newData;
    } else {
      eventObject.data = newData;
    }

    this.sendObject(eventObject);
  }
};

AGServerSocket.prototype.invoke = function (event, data, options) {
  return new Promise((resolve, reject) => {
    let eventObject = {
      event,
      cid: this._nextCallId()
    };
    if (data !== undefined) {
      eventObject.data = data;
    }

    let timeout = setTimeout(() => {
      let error = new TimeoutError(`Event response for "${event}" timed out`);
      delete this._callbackMap[eventObject.cid];
      reject(error);
    }, this.server.ackTimeout);

    this._callbackMap[eventObject.cid] = {
      callback: (err, result) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(result);
      },
      timeout
    };

    if (options && options.useCache && options.stringifiedData != null) {
      // Optimized
      this.send(options.stringifiedData);
    } else {
      this.sendObject(eventObject);
    }
  });
};

AGServerSocket.prototype.triggerAuthenticationEvents = function (oldAuthState) {
  if (oldAuthState !== this.AUTHENTICATED) {
    let stateChangeData = {
      oldAuthState,
      newAuthState: this.authState,
      authToken: this.authToken
    };
    this.emit('authStateChange', stateChangeData);
    this.server.emit('authenticationStateChange', {
      socket: this,
      ...stateChangeData
    });
  }
  this.emit('authenticate', {authToken: this.authToken});
  this.server.emit('authentication', {
    socket: this,
    authToken: this.authToken
  });
};

AGServerSocket.prototype.setAuthToken = async function (data, options) {
  let authToken = cloneDeep(data);
  let oldAuthState = this.authState;
  this.authState = this.AUTHENTICATED;

  if (options == null) {
    options = {};
  } else {
    options = cloneDeep(options);
    if (options.algorithm != null) {
      delete options.algorithm;
      let err = new InvalidArgumentsError(
        'Cannot change auth token algorithm at runtime - It must be specified as a config option on launch'
      );
      this.emitError(err);
    }
  }

  options.mutatePayload = true;
  let rejectOnFailedDelivery = options.rejectOnFailedDelivery;
  delete options.rejectOnFailedDelivery;
  let defaultSignatureOptions = this.server.defaultSignatureOptions;

  // We cannot have the exp claim on the token and the expiresIn option
  // set at the same time or else auth.signToken will throw an error.
  let expiresIn;
  if (options.expiresIn == null) {
    expiresIn = defaultSignatureOptions.expiresIn;
  } else {
    expiresIn = options.expiresIn;
  }
  if (authToken) {
    if (authToken.exp == null) {
      options.expiresIn = expiresIn;
    } else {
      delete options.expiresIn;
    }
  } else {
    options.expiresIn = expiresIn;
  }

  // Always use the default algorithm since it cannot be changed at runtime.
  if (defaultSignatureOptions.algorithm != null) {
    options.algorithm = defaultSignatureOptions.algorithm;
  }

  this.authToken = authToken;

  let sendAuthTokenToClient = async (signedToken) => {
    let tokenData = {
      token: signedToken
    };
    try {
      return await this.invoke('#setAuthToken', tokenData);
    } catch (err) {
      throw new AuthError(`Failed to deliver auth token to client - ${err}`);
    }
  };

  let signedAuthToken;

  try {
    signedAuthToken = await this.server.auth.signToken(authToken, this.server.signatureKey, options);
  } catch (error) {
    this.emitError(error);
    this._onClose(4002, error.toString());
    this.socket.close(4002);
    throw error;
  }

  if (this.authToken === authToken) {
    this.signedAuthToken = signedAuthToken;
    this.emit('authTokenSigned', {signedAuthToken});
  }

  this.triggerAuthenticationEvents(oldAuthState);
  try {
    await sendAuthTokenToClient(signedAuthToken);
  } catch (err) {
    this.emitError(err);
    if (rejectOnFailedDelivery) {
      throw err;
    }
  }
};

AGServerSocket.prototype.getAuthToken = function () {
  return this.authToken;
};

AGServerSocket.prototype.deauthenticateSelf = function () {
  let oldAuthState = this.authState;
  let oldAuthToken = this.authToken;
  this.signedAuthToken = null;
  this.authToken = null;
  this.authState = this.UNAUTHENTICATED;
  if (oldAuthState !== this.UNAUTHENTICATED) {
    let stateChangeData = {
      oldAuthState,
      newAuthState: this.authState
    };
    this.emit('authStateChange', stateChangeData);
    this.server.emit('authenticationStateChange', {
      socket: this,
      ...stateChangeData
    });
  }
  this.emit('deauthenticate', {oldAuthToken});
  this.server.emit('deauthentication', {
    socket: this,
    oldAuthToken
  });
};

AGServerSocket.prototype.deauthenticate = function () {
  this.deauthenticateSelf();
  return this.invoke('#removeAuthToken');
};

AGServerSocket.prototype.kickOut = function (channel, message) {
  delete this.channelSubscriptions[channel];
  this.channelSubscriptionsCount--;
  this.transmit('#kickOut', {channel, message});
  return this.server.brokerEngine.unsubscribeSocket(this, channel);
};

AGServerSocket.prototype.subscriptions = function () {
  return Object.keys(this.channelSubscriptions);
};

AGServerSocket.prototype.isSubscribed = function (channel) {
  return !!this.channelSubscriptions[channel];
};

AGServerSocket.prototype._processAuthTokenExpiry = function () {
  let token = this.getAuthToken();
  if (this.isAuthTokenExpired(token)) {
    this.deauthenticate();

    return new AuthTokenExpiredError(
      'The socket auth token has expired',
      token.exp
    );
  }
  return null;
};

AGServerSocket.prototype.isAuthTokenExpired = function (token) {
  if (token && token.exp != null) {
    let currentTime = Date.now();
    let expiryMilliseconds = token.exp * 1000;
    return currentTime > expiryMilliseconds;
  }
  return false;
};

AGServerSocket.prototype._processTokenError = function (err) {
  if (err) {
    if (err.name === 'TokenExpiredError') {
      let authError = new AuthTokenExpiredError(err.message, err.expiredAt);
      authError.isBadToken = true;
      return authError;
    }
    if (err.name === 'JsonWebTokenError') {
      let authError = new AuthTokenInvalidError(err.message);
      authError.isBadToken = true;
      return authError;
    }
    if (err.name === 'NotBeforeError') {
      let authError = new AuthTokenNotBeforeError(err.message, err.date);
      // In this case, the token is good; it's just not active yet.
      authError.isBadToken = false;
      return authError;
    }
    let authError = new AuthTokenError(err.message);
    authError.isBadToken = true;
    return authError;
  }
  return null;
};

AGServerSocket.prototype._emitBadAuthTokenError = function (error, signedAuthToken) {
  this.emit('badAuthToken', {
    authError: error,
    signedAuthToken
  });
  this.server.emit('badSocketAuthToken', {
    socket: this,
    authError: error,
    signedAuthToken
  });
};

AGServerSocket.prototype._processAuthToken = async function (signedAuthToken) {
  let verificationOptions = Object.assign({}, this.server.defaultVerificationOptions, {
    socket: this
  });
  let authToken;

  try {
    authToken = await this.server.auth.verifyToken(signedAuthToken, this.server.verificationKey, verificationOptions);
  } catch (error) {
    this.signedAuthToken = null;
    this.authToken = null;
    this.authState = this.UNAUTHENTICATED;

    let authTokenError = this._processTokenError(error);

    // If the error is related to the JWT being badly formatted, then we will
    // treat the error as a socket error.
    if (error && signedAuthToken != null) {
      this.emitError(authTokenError);
      if (authTokenError.isBadToken) {
        this._emitBadAuthTokenError(authTokenError, signedAuthToken);
      }
    }
    throw authTokenError;
  }

  this.signedAuthToken = signedAuthToken;
  this.authToken = authToken;
  this.authState = this.AUTHENTICATED;

  let action = new Action();
  action.type = this.server.ACTION_AUTHENTICATE;
  action.socket = this;
  action.signedAuthToken = this.signedAuthToken;
  action.authToken = this.authToken;

  try {
    await this.server._processMiddlewareAction(this._middlewareInboundStream, action, this);
  } catch (error) {
    this.authToken = null;
    this.authState = this.UNAUTHENTICATED;

    if (error.isBadToken) {
      this._emitBadAuthTokenError(error, signedAuthToken);
    }
    throw error;
  }
};

module.exports = AGServerSocket;
