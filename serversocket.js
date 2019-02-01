// TODO 2: Allow disconnecting out of band (disconnect message should not wait to be processed in stream sequence).

const cloneDeep = require('lodash.clonedeep');
const WritableAsyncIterableStream = require('writable-async-iterable-stream');
const StreamDemux = require('stream-demux');
const AsyncStreamEmitter = require('async-stream-emitter');
const AGAction = require('./action');
const AGRequest = require('ag-request');

const scErrors = require('sc-errors');
const InvalidArgumentsError = scErrors.InvalidArgumentsError;
const SocketProtocolError = scErrors.SocketProtocolError;
const TimeoutError = scErrors.TimeoutError;
const BadConnectionError = scErrors.BadConnectionError;
const InvalidActionError = scErrors.InvalidActionError;
const AuthError = scErrors.AuthError;
const AuthTokenExpiredError = scErrors.AuthTokenExpiredError;
const AuthTokenInvalidError = scErrors.AuthTokenInvalidError;
const AuthTokenNotBeforeError = scErrors.AuthTokenNotBeforeError;
const AuthTokenError = scErrors.AuthTokenError;
const BrokerError = scErrors.BrokerError;

const HANDSHAKE_REJECTION_STATUS_CODE = 4008;

function AGServerSocket(id, server, socket, protocolVersion) {
  AsyncStreamEmitter.call(this);

  this.id = id;
  this.server = server;
  this.socket = socket;
  this.state = this.CONNECTING;
  this.authState = this.UNAUTHENTICATED;
  this.protocolVersion = protocolVersion;

  this._receiverDemux = new StreamDemux();
  this._procedureDemux = new StreamDemux();

  this.request = this.socket.upgradeReq;

  this.inboundReceivedMessageCount = 0;
  this.inboundProcessedMessageCount = 0;

  this.outboundPreparedMessageCount = 0;
  this.outboundSentMessageCount = 0;

  this.cloneData = this.server.options.cloneData;

  this._rawInboundMessageStream = new WritableAsyncIterableStream();
  this._outboundPacketStream = new WritableAsyncIterableStream();

  this.middlewareInboundRawStream = new WritableAsyncIterableStream();
  this.middlewareInboundRawStream.type = this.server.MIDDLEWARE_INBOUND_RAW;

  this.middlewareInboundStream = new WritableAsyncIterableStream();
  this.middlewareInboundStream.type = this.server.MIDDLEWARE_INBOUND;

  this.middlewareOutboundStream = new WritableAsyncIterableStream();
  this.middlewareOutboundStream.type = this.server.MIDDLEWARE_OUTBOUND;

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

  this.isBufferingBatch = false;
  this.isBatching = false;
  this.batchOnHandshake = this.server.options.batchOnHandshake;
  this.batchOnHandshakeDuration = this.server.options.batchOnHandshakeDuration;
  this.batchInterval = this.server.options.batchInterval;
  this._batchBuffer = [];

  this._batchingIntervalId = null;
  this._cid = 1;
  this._callbackMap = {};

  this.channelSubscriptions = {};
  this.channelSubscriptionsCount = 0;

  this.socket.on('error', (err) => {
    this.emitError(err);
  });

  this.socket.on('close', (code, data) => {
    this._onClose(code, data);
  });

  let pongMessage;
  if (this.protocolVersion === 1) {
    pongMessage = '#2';
    this._sendPing = () => {
      if (this.state !== this.CLOSED) {
        this.send('#1');
      }
    };
  } else {
    pongMessage = '';
    this._sendPing = () => {
      if (this.state !== this.CLOSED) {
        this.send('');
      }
    };
  }

  if (!this.server.pingTimeoutDisabled) {
    this._pingIntervalTicker = setInterval(() => {
      this._sendPing();
    }, this.server.pingInterval);
  }
  this._resetPongTimeout();

  this._handshakeTimeoutRef = setTimeout(() => {
    this._handleHandshakeTimeout();
  }, this.server.handshakeTimeout);

  this.server.pendingClients[this.id] = this;
  this.server.pendingClientsCount++;

  this._handleRawInboundMessageStream(pongMessage);
  this._handleOutboundPacketStream();

  // Receive incoming raw messages
  this.socket.on('message', async (message, flags) => {
    this.inboundReceivedMessageCount++;

    let isPong = message === pongMessage;

    if (isPong) {
      this._resetPongTimeout();
    }

    if (this.server.hasMiddleware(this.server.MIDDLEWARE_INBOUND_RAW)) {
      let action = new AGAction();
      action.socket = this;
      action.type = AGAction.MESSAGE;
      action.data = message;

      try {
        let {data} = await this.server._processMiddlewareAction(this.middlewareInboundRawStream, action, this);
        message = data;
      } catch (error) {
        this.inboundProcessedMessageCount++;
        return;
      }
    }

    this._rawInboundMessageStream.write(message);
    this.emit('message', {message});
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

Object.defineProperty(AGServerSocket.prototype, 'inboundBackpressure', {
  get: function () {
    return this.inboundReceivedMessageCount - this.inboundProcessedMessageCount;
  }
});

Object.defineProperty(AGServerSocket.prototype, 'outboundBackpressure', {
  get: function () {
    return this.outboundPreparedMessageCount - this.outboundSentMessageCount;
  }
});

AGServerSocket.prototype._startBatchOnHandshake = function () {
  this._startBatching();
  setTimeout(() => {
    if (!this.isBatching) {
      this._stopBatching();
    }
  }, this.batchOnHandshakeDuration);
};

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


AGServerSocket.prototype._handleRawInboundMessageStream = async function (pongMessage) {
  for await (let message of this._rawInboundMessageStream) {
    this.inboundProcessedMessageCount++;
    let isPong = message === pongMessage;

    if (isPong) {
      let token = this.getAuthToken();
      if (this.isAuthTokenExpired(token)) {
        this.deauthenticate();
      }
      continue;
    }

    let packet;
    try {
      packet = this.decode(message);
    } catch (error) {
      if (error.name === 'Error') {
        error.name = 'InvalidMessageError';
      }
      this.emitError(error);
      continue;
    }

    if (Array.isArray(packet)) {
      let len = packet.length;
      for (let i = 0; i < len; i++) {
        await this._processInboundPacket(packet[i], message);
      }
    } else {
      await this._processInboundPacket(packet, message);
    }
  }
};

AGServerSocket.prototype._handleHandshakeTimeout = function () {
  let middlewareHandshakeStream = this.request[this.server.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM];
  this.disconnect(4005);
};

AGServerSocket.prototype._processHandshakeRequest = async function (request) {
  let data = request.data || {};
  let signedAuthToken = data.authToken || null;
  clearTimeout(this._handshakeTimeoutRef);

  let action = new AGAction();
  action.request = this.request;
  action.socket = this;
  action.type = AGAction.HANDSHAKE_AG;

  let middlewareHandshakeStream = this.request[this.server.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM];

  try {
    await this.server._processMiddlewareAction(middlewareHandshakeStream, action);
  } catch (error) {
    if (error.statusCode == null) {
      error.statusCode = HANDSHAKE_REJECTION_STATUS_CODE;
    }
    request.error(error);
    this.disconnect(error.statusCode);
    return;
  }

  let clientSocketStatus = {
    id: this.id,
    pingTimeout: this.server.pingTimeout
  };
  let serverSocketStatus = {
    id: this.id,
    pingTimeout: this.server.pingTimeout
  };

  let oldAuthState = this.authState;
  try {
    await this._processAuthToken(signedAuthToken);
    if (this.state === this.CLOSED) {
      return;
    }
  } catch (error) {
    if (signedAuthToken != null) {
      // Because the token is optional as part of the handshake, we don't count
      // it as an error if the token wasn't provided.
      clientSocketStatus.authError = scErrors.dehydrateError(error);
      serverSocketStatus.authError = error;

      if (error.isBadToken) {
        this.deauthenticate();
      }
    }
  }
  clientSocketStatus.isAuthenticated = !!this.authToken;
  serverSocketStatus.isAuthenticated = clientSocketStatus.isAuthenticated;

  if (this.server.pendingClients[this.id]) {
    delete this.server.pendingClients[this.id];
    this.server.pendingClientsCount--;
  }
  this.server.clients[this.id] = this;
  this.server.clientsCount++;

  this.state = this.OPEN;

  if (clientSocketStatus.isAuthenticated) {
    // Needs to be executed after the connection event to allow
    // consumers to be setup from inside the connection loop.
    (async () => {
      await this.listener('connect').once();
      this.triggerAuthenticationEvents(oldAuthState);
    })();
  }

  // Treat authentication failure as a 'soft' error
  request.end(clientSocketStatus);

  if (this.batchOnHandshake) {
    this._startBatchOnHandshake();
  }

  this.emit('connect', serverSocketStatus);
  this.server.emit('connection', {socket: this, ...serverSocketStatus});

  middlewareHandshakeStream.close();
};

AGServerSocket.prototype._processAuthenticateRequest = async function (request) {
  let signedAuthToken = request.data;
  let oldAuthState = this.authState;
  try {
    await this._processAuthToken(signedAuthToken);
  } catch (error) {
    if (error.isBadToken) {
      this.deauthenticate();
      request.error(error);

      return;
    }

    request.end({
      isAuthenticated: !!this.authToken,
      authError: signedAuthToken == null ? null : scErrors.dehydrateError(error)
    });

    return;
  }
  this.triggerAuthenticationEvents(oldAuthState);
  request.end({
    isAuthenticated: !!this.authToken,
    authError: null
  });
};

AGServerSocket.prototype._subscribeSocket = async function (channelName, subscriptionOptions) {
  if (channelName === undefined || !subscriptionOptions) {
    throw new InvalidActionError(`Socket ${this.id} provided a malformated channel payload`);
  }

  if (this.server.socketChannelLimit && this.channelSubscriptionsCount >= this.server.socketChannelLimit) {
    throw new InvalidActionError(
      `Socket ${this.id} tried to exceed the channel subscription limit of ${this.server.socketChannelLimit}`
    );
  }

  if (typeof channelName !== 'string') {
    throw new InvalidActionError(`Socket ${this.id} provided an invalid channel name`);
  }

  if (this.channelSubscriptionsCount == null) {
    this.channelSubscriptionsCount = 0;
  }
  if (this.channelSubscriptions[channelName] == null) {
    this.channelSubscriptions[channelName] = true;
    this.channelSubscriptionsCount++;
  }

  try {
    await this.server.brokerEngine.subscribeSocket(this, channelName);
  } catch (error) {
    delete this.channelSubscriptions[channelName];
    this.channelSubscriptionsCount--;
    throw error;
  }
  this.emit('subscribe', {
    channel: channelName,
    subscriptionOptions
  });
  this.server.emit('subscription', {
    socket: this,
    channel: channelName,
    subscriptionOptions
  });
};

AGServerSocket.prototype._processSubscribeRequest = async function (request) {
  let subscriptionOptions = Object.assign({}, request.data);
  let channelName = subscriptionOptions.channel;
  delete subscriptionOptions.channel;

  if (this.state === this.OPEN) {
    try {
      await this._subscribeSocket(channelName, subscriptionOptions);
    } catch (err) {
      let error = new BrokerError(`Failed to subscribe socket to the ${channelName} channel - ${err}`);
      this.emitError(error);
      request.error(error);

      return;
    }

    request.end();

    return;
  }
  // This is an invalid state; it means the client tried to subscribe before
  // having completed the handshake.
  let error = new InvalidActionError('Cannot subscribe socket to a channel before it has completed the handshake');
  this.emitError(error);
  request.error(error);
};

AGServerSocket.prototype._unsubscribeFromAllChannels = function () {
  Object.keys(this.channelSubscriptions).forEach((channelName) => {
    this._unsubscribe(channelName);
  });
};

AGServerSocket.prototype._unsubscribe = function (channel) {
  if (typeof channel !== 'string') {
    throw new InvalidActionError(
      `Socket ${this.id} tried to unsubscribe from an invalid channel name`
    );
  }
  if (!this.channelSubscriptions[channel]) {
    throw new InvalidActionError(
      `Socket ${this.id} tried to unsubscribe from a channel which it is not subscribed to`
    );
  }

  delete this.channelSubscriptions[channel];
  if (this.channelSubscriptionsCount != null) {
    this.channelSubscriptionsCount--;
  }

  this.server.brokerEngine.unsubscribeSocket(this, channel);

  this.emit('unsubscribe', {channel});
  this.server.emit('unsubscription', {socket: this, channel});
};

AGServerSocket.prototype._processUnsubscribePacket = async function (packet) {
  let channel = packet.data;
  try {
    this._unsubscribe(channel);
  } catch (err) {
    let error = new BrokerError(
      `Failed to unsubscribe socket from the ${channel} channel - ${err}`
    );
    this.emitError(error);
  }
};

AGServerSocket.prototype._processUnsubscribeRequest = async function (request) {
  let channel = request.data;
  try {
    this._unsubscribe(channel);
  } catch (err) {
    let error = new BrokerError(
      `Failed to unsubscribe socket from the ${channel} channel - ${err}`
    );
    this.emitError(error);
    request.error(error);
    return;
  }
  request.end();
};

AGServerSocket.prototype._processInboundPublishPacket = async function (packet) {
  let data = packet.data || {};
  if (typeof data.channel !== 'string') {
    let error = new InvalidActionError(`Socket ${this.id} tried to invoke publish to an invalid "${data.channel}" channel`);
    this.emitError(error);
    return;
  }
  try {
    await this.server.exchange.invokePublish(data.channel, data.data);
  } catch (error) {
    this.emitError(error);
  }
};

AGServerSocket.prototype._processInboundPublishRequest = async function (request) {
  let data = request.data || {};
  if (typeof data.channel !== 'string') {
    let error = new InvalidActionError(`Socket ${this.id} tried to transmit publish to an invalid "${data.channel}" channel`);
    this.emitError(error);
    request.error(error);
    return;
  }
  try {
    await this.server.exchange.invokePublish(data.channel, data.data);
  } catch (error) {
    this.emitError(error);
    request.error(error);
    return;
  }
  request.end();
};

AGServerSocket.prototype._processInboundPacket = async function (packet, message) {
  if (packet && packet.event != null) {
    let eventName = packet.event;
    let isRPC = packet.cid != null;

    if (eventName === '#handshake') {
      let request = new AGRequest(this, packet.cid, eventName, packet.data);
      await this._processHandshakeRequest(request);
      this._procedureDemux.write(eventName, request);

      return;
    }
    if (eventName === '#authenticate') {
      // Let AGServer handle these events.
      let request = new AGRequest(this, packet.cid, eventName, packet.data);
      await this._processAuthenticateRequest(request);
      this._procedureDemux.write(eventName, request);

      return;
    }
    if (eventName === '#removeAuthToken') {
      this.deauthenticateSelf();
      this._receiverDemux.write(eventName, packet.data);

      return;
    }

    let action = new AGAction();
    action.socket = this;

    let tokenExpiredError = this._processAuthTokenExpiry();
    if (tokenExpiredError) {
      action.authTokenExpiredError = tokenExpiredError;
    }

    let isPublish = eventName === '#publish';
    let isSubscribe = eventName === '#subscribe';
    let isUnsubscribe = eventName === '#unsubscribe';

    if (isPublish) {
      if (!this.server.allowClientPublish) {
        let error = new InvalidActionError('Client publish feature is disabled');
        this.emitError(error);

        if (isRPC) {
          let request = new AGRequest(this, packet.cid, eventName, packet.data);
          request.error(error);
        }
        return;
      }
      action.type = AGAction.PUBLISH_IN;
      if (packet.data) {
        action.channel = packet.data.channel;
        action.data = packet.data.data;
      }
    } else if (isSubscribe) {
      action.type = AGAction.SUBSCRIBE;
      if (packet.data) {
        action.channel = packet.data.channel;
        action.data = packet.data.data;
      }
    } else if (isUnsubscribe) {
      if (isRPC) {
        let request = new AGRequest(this, packet.cid, eventName, packet.data);
        await this._processUnsubscribeRequest(request);
        this._procedureDemux.write(eventName, request);
        return;
      }
      await this._processUnsubscribePacket(packet);
      this._receiverDemux.write(eventName, packet.data);
      return;
    } else {
      if (isRPC) {
        action.type = AGAction.INVOKE;
        action.procedure = packet.event;
        if (packet.data !== undefined) {
          action.data = packet.data;
        }
      } else {
        action.type = AGAction.TRANSMIT;
        action.receiver = packet.event;
        if (packet.data !== undefined) {
          action.data = packet.data;
        }
      }
    }

    let newData;

    if (isRPC) {
      let request = new AGRequest(this, packet.cid, eventName, packet.data);
      try {
        let {data} = await this.server._processMiddlewareAction(this.middlewareInboundStream, action, this);
        newData = data;
      } catch (error) {
        request.error(error);

        return;
      }

      if (isSubscribe) {
        if (!request.data) {
          request.data = {};
        }
        request.data.data = newData;
        await this._processSubscribeRequest(request);
      } else if (isPublish) {
        if (!request.data) {
          request.data = {};
        }
        request.data.data = newData;
        await this._processInboundPublishRequest(request);
      } else {
        request.data = newData;
      }

      this._procedureDemux.write(eventName, request);

      return;
    }

    try {
      let {data} = await this.server._processMiddlewareAction(this.middlewareInboundStream, action, this);
      newData = data;
    } catch (error) {

      return;
    }

    if (isPublish) {
      await this._processInboundPublishPacket(packet);
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

AGServerSocket.prototype._abortAllPendingEventsDueToBadConnection = function (failureType) {
  Object.keys(this._callbackMap || {}).forEach((i) => {
    let eventObject = this._callbackMap[i];
    delete this._callbackMap[i];

    clearTimeout(eventObject.timeout);
    delete eventObject.timeout;

    let errorMessage = `Event "${eventObject.event}" was aborted due to a bad connection`;
    let badConnectionError = new BadConnectionError(errorMessage, failureType);

    let callback = eventObject.callback;
    delete eventObject.callback;

    callback.call(eventObject, badConnectionError, eventObject);
  });
};

AGServerSocket.prototype._onClose = function (code, reason) {
  clearInterval(this._pingIntervalTicker);
  clearTimeout(this._pingTimeoutTicker);

  this._cancelBatching();

  if (this.state === this.CLOSED) {
    this._abortAllPendingEventsDueToBadConnection('connectAbort');
  } else {
    let prevState = this.state;
    this.state = this.CLOSED;
    if (prevState === this.CONNECTING) {
      this._abortAllPendingEventsDueToBadConnection('connectAbort');
      this.emit('connectAbort', {code, reason});
      this.server.emit('connectionAbort', {
        socket: this,
        code,
        reason
      });
    } else {
      this._abortAllPendingEventsDueToBadConnection('disconnect');
      this.emit('disconnect', {code, reason});
      this.server.emit('disconnection', {
        socket: this,
        code,
        reason
      });
    }
    this.emit('close', {code, reason});
    this.server.emit('closure', {
      socket: this,
      code,
      reason
    });
    this._unsubscribeFromAllChannels();

    clearTimeout(this._handshakeTimeoutRef);
    let isClientFullyConnected = !!this.server.clients[this.id];

    if (isClientFullyConnected) {
      delete this.server.clients[this.id];
      this.server.clientsCount--;
    }

    let isClientPending = !!this.server.pendingClients[this.id];
    if (isClientPending) {
      delete this.server.pendingClients[this.id];
      this.server.pendingClientsCount--;
    }

    let middlewareHandshakeStream = this.request[this.server.SYMBOL_MIDDLEWARE_HANDSHAKE_STREAM];
    middlewareHandshakeStream.close();
    this.middlewareInboundRawStream.close();
    this.middlewareInboundStream.close();
    this.middlewareOutboundStream.close();
    this._rawInboundMessageStream.close();
    this._outboundPacketStream.close();

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

AGServerSocket.prototype.startBatch = function () {
  this.isBufferingBatch = true;
  this._batchBuffer = [];
};

AGServerSocket.prototype.flushBatch = function () {
  this.isBufferingBatch = false;
  if (!this._batchBuffer.length) {
    return;
  }
  let serializedBatch = this.serializeObject(this._batchBuffer);
  this._batchBuffer = [];
  this.send(serializedBatch);
};

AGServerSocket.prototype.cancelBatch = function () {
  this.isBufferingBatch = false;
  this._batchBuffer = [];
};

AGServerSocket.prototype._startBatching = function () {
  if (this._batchingIntervalId != null) {
    return;
  }
  this.startBatch();
  this._batchingIntervalId = setInterval(() => {
    this.flushBatch();
    this.startBatch();
  }, this.batchInterval);
};

AGServerSocket.prototype.startBatching = function () {
  this.isBatching = true;
  this._startBatching();
};

AGServerSocket.prototype._stopBatching = function () {
  if (this._batchingIntervalId != null) {
    clearInterval(this._batchingIntervalId);
  }
  this._batchingIntervalId = null;
  this.flushBatch();
};

AGServerSocket.prototype.stopBatching = function () {
  this.isBatching = false;
  this._stopBatching();
};

AGServerSocket.prototype._cancelBatching = function () {
  if (this._batchingIntervalId != null) {
    clearInterval(this._batchingIntervalId);
  }
  this._batchingIntervalId = null;
  this.cancelBatch();
};

AGServerSocket.prototype.cancelBatching = function () {
  this.isBatching = false;
  this._cancelBatching();
};

AGServerSocket.prototype.serializeObject = function (object) {
  let str;
  try {
    str = this.encode(object);
  } catch (error) {
    this.emitError(error);
    return null;
  }
  return str;
};

AGServerSocket.prototype.sendObject = function (object) {
  if (this.isBufferingBatch) {
    this._batchBuffer.push(object);
    return;
  }
  let str = this.serializeObject(object);
  if (str != null) {
    this.send(str);
  }
};

AGServerSocket.prototype._handleOutboundPacketStream = async function () {
  for await (let packet of this._outboundPacketStream) {
    if (packet.resolve) {
      // Invoke has no middleware, so there is no need to await here.
      (async () => {
        let result;
        try {
          result = await this._invoke(packet.event, packet.data, packet.options);
        } catch (error) {
          packet.reject(error);
          return;
        }
        packet.resolve(result);
      })();

      this.outboundSentMessageCount++;
      continue;
    }
    await this._transmit(packet.event, packet.data, packet.options);
    this.outboundSentMessageCount++;
  }
};

AGServerSocket.prototype.transmit = async function (event, data, options) {
  if (this.state !== this.OPEN) {
    return;
  }
  if (this.cloneData) {
    data = cloneDeep(data);
  }
  this.outboundPreparedMessageCount++;
  this._outboundPacketStream.write({
    event,
    data,
    options
  });
};

AGServerSocket.prototype.invoke = async function (event, data, options) {
  if (this.state !== this.OPEN) {
    let errorMessage = `Socket invoke "${event}" was aborted due to a bad connection`;
    throw new BadConnectionError(errorMessage, 'connectAbort');
  }
  if (this.cloneData) {
    data = cloneDeep(data);
  }
  this.outboundPreparedMessageCount++;
  return new Promise((resolve, reject) => {
    this._outboundPacketStream.write({
      event,
      data,
      options,
      resolve,
      reject
    });
  });
};

AGServerSocket.prototype._transmit = async function (event, data, options) {
  let newData;
  let useCache = options ? options.useCache : false;
  let packet = {event, data};
  let isPublish = event === '#publish';
  if (isPublish) {
    let action = new AGAction();
    action.socket = this;
    action.type = AGAction.PUBLISH_OUT;

    if (data !== undefined) {
      action.channel = data.channel;
      action.data = data.data;
    }
    useCache = !this.server.hasMiddleware(this.middlewareOutboundStream.type);

    try {
      let {data, options} = await this.server._processMiddlewareAction(this.middlewareOutboundStream, action, this);
      newData = data;
      useCache = options == null ? useCache : options.useCache;
    } catch (error) {

      return;
    }
  } else {
    newData = packet.data;
  }

  if (options && useCache && options.stringifiedData != null && !this.isBufferingBatch) {
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

AGServerSocket.prototype._invoke = async function (event, data, options) {
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
      event,
      callback: (err, result) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(result);
      },
      timeout
    };

    if (options && options.useCache && options.stringifiedData != null && !this.isBufferingBatch) {
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

  let tokenData = {
    token: signedAuthToken
  };

  if (rejectOnFailedDelivery) {
    try {
      await this.invoke('#setAuthToken', tokenData);
    } catch (err) {
      let error = new AuthError(`Failed to deliver auth token to client - ${err}`);
      this.emitError(error);
      throw error;
    }
    return;
  }
  this.transmit('#setAuthToken', tokenData);
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

AGServerSocket.prototype.deauthenticate = async function (options) {
  this.deauthenticateSelf();
  if (options && options.rejectOnFailedDelivery) {
    try {
      await this.invoke('#removeAuthToken');
    } catch (error) {
      this.emitError(error);
      if (options && options.rejectOnFailedDelivery) {
        throw error;
      }
    }
    return;
  }
  this.transmit('#removeAuthToken');
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

  let action = new AGAction();
  action.socket = this;
  action.type = AGAction.AUTHENTICATE;
  action.signedAuthToken = this.signedAuthToken;
  action.authToken = this.authToken;

  try {
    await this.server._processMiddlewareAction(this.middlewareInboundStream, action, this);
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
