var defaults = require('lodash.defaults');
var SCEmitter = require('sc-emitter').SCEmitter;
var Response = require('./response').Response;

var scErrors = require('sc-errors');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;
var InvalidMessageError = scErrors.InvalidMessageError;
var SocketProtocolError = scErrors.SocketProtocolError;
var TimeoutError = scErrors.TimeoutError;


var SCSocket = function (id, server, socket) {
  var self = this;

  SCEmitter.call(this);

  this._localEvents = {
    'open': 1,
    'subscribe': 1,
    'unsubscribe': 1,
    'disconnect': 1,
    '_disconnect': 1,
    'message': 1,
    'error': 1,
    'authenticate': 1,
    'deauthenticate': 1,
    'raw': 1
  };

  this._autoAckEvents = {
    '#publish': 1
  };

  this.id = id;
  this.server = server;
  this.socket = socket;
  this.state = this.CONNECTING;

  this.request = this.socket.upgradeReq || {};

  // If uws module is used.
  if (!this.request.connection) {
    this.request.connection = this.socket._socket;
  }
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

  this.channelSubscriptions = {};
  this.channelSubscriptionsCount = 0;

  this.socket.on('error', function (err) {
    SCEmitter.prototype.emit.call(self, 'error', err);
  });

  this.socket.on('close', function (code, data) {
    self._onSCClose(code, data);
  });

  this._pingIntervalTicker = setInterval(this._sendPing.bind(this), this.server.pingInterval);
  this._resetPongTimeout();

  // Receive incoming raw messages
  this.socket.on('message', function (message, flags) {
    self._resetPongTimeout();

    SCEmitter.prototype.emit.call(self, 'message', message);

    var obj = self.decode(message);

    // If pong
    if (obj == '#2') {
      var token = self.getAuthToken();
      if (self.server.isAuthTokenExpired(token)) {
        self.deauthenticate();
      }
    } else {
      if (obj == null) {
        var err = new InvalidMessageError('Received empty message');
        SCEmitter.prototype.emit.call(self, 'error', err);

      } else if (obj.event) {
        var eventName = obj.event;

        if (self._localEvents[eventName] == null) {
          var response = new Response(self, obj.cid);
          self.server.verifyInboundEvent(self, eventName, obj.data, function (err, newData) {
            if (err) {
              response.error(err);
            } else {
              var eventData = newData;
              if (eventName == '#disconnect') {
                var disconnectData = eventData || {};
                self._onSCClose(disconnectData.code, disconnectData.data);
              } else {
                if (self._autoAckEvents[eventName]) {
                  response.end();
                  SCEmitter.prototype.emit.call(self, eventName, eventData);
                } else {
                  SCEmitter.prototype.emit.call(self, eventName, eventData, response.callback.bind(response));
                }
              }
            }
          });
        }
      } else if (obj.rid != null) {
        // If incoming message is a response to a previously sent message
        var ret = self._callbackMap[obj.rid];
        if (ret) {
          clearTimeout(ret.timeout);
          delete self._callbackMap[obj.rid];
          var rehydratedError = scErrors.hydrateError(obj.error);
          ret.callback(rehydratedError, obj.data);
        }
      } else {
        // The last remaining case is to treat the message as raw
        SCEmitter.prototype.emit.call(self, 'raw', message);
      }
    }
  });
};

SCSocket.prototype = Object.create(SCEmitter.prototype);

SCSocket.CONNECTING = SCSocket.prototype.CONNECTING = 'connecting';
SCSocket.OPEN = SCSocket.prototype.OPEN = 'open';
SCSocket.CLOSED = SCSocket.prototype.CLOSED = 'closed';

SCSocket.AUTHENTICATED = SCSocket.prototype.AUTHENTICATED = 'authenticated';
SCSocket.UNAUTHENTICATED = SCSocket.prototype.UNAUTHENTICATED = 'unauthenticated';

SCSocket.ignoreStatuses = scErrors.socketProtocolIgnoreStatuses;
SCSocket.errorStatuses = scErrors.socketProtocolErrorStatuses;

SCSocket.prototype._sendPing = function () {
  if (this.state != this.CLOSED) {
    this.sendObject('#1');
  }
};

SCSocket.prototype._resetPongTimeout = function () {
  var self = this;

  clearTimeout(this._pingTimeoutTicker);
  this._pingTimeoutTicker = setTimeout(function() {
    self._onSCClose(4001);
    self.socket.close(4001);
  }, this.server.pingTimeout);
};

SCSocket.prototype._nextCallId = function () {
  return this._cid++;
};

SCSocket.prototype.getState = function () {
  return this.state;
};

SCSocket.prototype.getBytesReceived = function () {
  return this.socket.bytesReceived;
};

SCSocket.prototype._onSCClose = function (code, data) {
  clearInterval(this._pingIntervalTicker);
  clearTimeout(this._pingTimeoutTicker);

  if (this.state != this.CLOSED) {
    this.state = this.CLOSED;

    // Private disconnect event for internal use only
    SCEmitter.prototype.emit.call(this, '_disconnect', code, data);
    SCEmitter.prototype.emit.call(this, 'disconnect', code, data);

    if (!SCSocket.ignoreStatuses[code]) {
      var failureMessage;
      if (data) {
        failureMessage = 'Socket connection failed: ' + data;
      } else {
        failureMessage = 'Socket connection failed for unknown reasons';
      }
      var err = new SocketProtocolError(SCSocket.errorStatuses[code] || failureMessage, code);
      SCEmitter.prototype.emit.call(this, 'error', err);
    }
  }
};

SCSocket.prototype.disconnect = function (code, data) {
  code = code || 1000;

  if (this.state != this.CLOSED) {
    var packet = {
      code: code,
      data: data
    };
    this.emit('#disconnect', packet);
    this._onSCClose(code, data);
    this.socket.close(code);
  }
};

SCSocket.prototype.terminate = function () {
  this.socket.terminate();
};

SCSocket.prototype.send = function (data, options) {
  var self = this;

  this.socket.send(data, options, function (err) {
    if (err) {
      self._onSCClose(1006, err.toString());
    }
  });
};

SCSocket.prototype.decode = function (message) {
  return this.server.codec.decode(message);
};

SCSocket.prototype.encode = function (object) {
  return this.server.codec.encode(object);
};

SCSocket.prototype.sendObject = function (object) {
  var str;
  try {
    str = this.encode(object);
  } catch (err) {
    SCEmitter.prototype.emit.call(this, 'error', err);
  }
  if (str != null) {
    this.send(str);
  }
};

SCSocket.prototype.emit = function (event, data, callback, options) {
  var self = this;

  if (this._localEvents[event] == null) {
    this.server.verifyOutboundEvent(this, event, data, options, function (err, newData) {
      var eventObject = {
        event: event
      };
      if (newData !== undefined) {
        eventObject.data = newData;
      }

      if (err) {
        if (callback) {
          eventObject.cid = self._nextCallId();
          callback(err, eventObject);
        }
      } else {
        if (callback) {
          eventObject.cid = self._nextCallId();
          var timeout = setTimeout(function () {
            var error = new TimeoutError("Event response for '" + event + "' timed out");

            delete self._callbackMap[eventObject.cid];
            callback(error, eventObject);
          }, self.server.ackTimeout);

          self._callbackMap[eventObject.cid] = {callback: callback, timeout: timeout};
        }
        if (options && options.useCache && options.stringifiedData != null) {
          // Optimized
          self.send(options.stringifiedData);
        } else {
          self.sendObject(eventObject);
        }
      }
    });
  } else {
    SCEmitter.prototype.emit.apply(this, arguments);
  }
};

SCSocket.prototype.setAuthToken = function (data, options, callback) {
  var self = this;

  this.authToken = data;
  this.authState = this.AUTHENTICATED;

  if (options != null && options.algorithm != null) {
    delete options.algorithm;
    var err = new InvalidArgumentsError('Cannot change auth token algorithm at runtime - It must be specified as a config option on launch');
    SCEmitter.prototype.emit.call(this, 'error', err);
  }
  options = defaults({}, options, this.server.defaultSignatureOptions);
  this.server.auth.signToken(data, this.server.signatureKey, options, function (err, signedToken) {
    if (err) {
      self._onSCClose(4002, err);
      self.socket.close(4002);
      callback && callback(err);
    } else {
      var tokenData = {
        token: signedToken
      };
      self.emit('#setAuthToken', tokenData, callback);
    }
  });
};

SCSocket.prototype.getAuthToken = function () {
  return this.authToken;
};

SCSocket.prototype.deauthenticate = function (callback) {
  this.authToken = null;
  this.authState = this.UNAUTHENTICATED;
  this.emit('#removeAuthToken', null, callback);
};

SCSocket.prototype.kickOut = function (channel, message, callback) {
  if (channel == null) {
    for (var i in this.channelSubscriptions) {
      if (this.channelSubscriptions.hasOwnProperty(i)) {
        this.emit('#kickOut', {message: message, channel: i});
      }
    }
  } else {
    this.emit('#kickOut', {message: message, channel: channel});
  }
  this.server.brokerEngine.unsubscribeSocket(this, channel, callback);
};

SCSocket.prototype.subscriptions = function () {
  var subs = [];
  for (var i in this.channelSubscriptions) {
    if (this.channelSubscriptions.hasOwnProperty(i)) {
      subs.push(i);
    }
  }
  return subs;
};

SCSocket.prototype.isSubscribed = function (channel) {
  return !!this.channelSubscriptions[channel];
};

module.exports = SCSocket;
