var assert = require('assert');
var socketClusterServer = require('../');
var socketCluster = require('socketcluster-client');

var PORT = 8008;

var clientOptions = {
  hostname: '127.0.0.1',
  port: PORT
};

var serverOptions = {
  authKey: 'testkey'
};

var allowedUsers = {
  bob: true,
  alice: true
};

var TEN_DAYS_IN_SECONDS = 60 * 60 * 24 * 10;

var server, client;

var connectionHandler = function (socket) {
  socket.on('login', function (userDetails, respond) {
    if (allowedUsers[userDetails.username]) {
      socket.setAuthToken(userDetails);
      respond();
    } else {
      var err = new Error('Failed to login');
      err.name = 'FailedLoginError';
      respond(err);
    }
  });
  socket.on('loginWithTenDayExpiry', function (userDetails, respond) {
    if (allowedUsers[userDetails.username]) {
      socket.setAuthToken(userDetails, {
        expiresIn: TEN_DAYS_IN_SECONDS
      });
      respond();
    } else {
      var err = new Error('Failed to login');
      err.name = 'FailedLoginError';
      respond(err);
    }
  });
  socket.on('loginWithTenDayExp', function (userDetails, respond) {
    if (allowedUsers[userDetails.username]) {
      userDetails.exp = Math.round(Date.now() / 1000) + TEN_DAYS_IN_SECONDS;
      socket.setAuthToken(userDetails);
      respond();
    } else {
      var err = new Error('Failed to login');
      err.name = 'FailedLoginError';
      respond(err);
    }
  });
  socket.on('loginWithTenDayExpAndExpiry', function (userDetails, respond) {
    if (allowedUsers[userDetails.username]) {
      userDetails.exp = Math.round(Date.now() / 1000) + TEN_DAYS_IN_SECONDS;
      socket.setAuthToken(userDetails, {
        expiresIn: TEN_DAYS_IN_SECONDS * 100 // 1000 days
      });
      respond();
    } else {
      var err = new Error('Failed to login');
      err.name = 'FailedLoginError';
      respond(err);
    }
  });
  socket.on('loginWithIssAndIssuer', function (userDetails, respond) {
    if (allowedUsers[userDetails.username]) {
      userDetails.iss = 'foo';
      socket.setAuthToken(userDetails, {
        issuer: 'bar'
      });
      respond();
    } else {
      var err = new Error('Failed to login');
      err.name = 'FailedLoginError';
      respond(err);
    }
  });
  socket.on('setAuthKey', function (newAuthKey, respond) {
    server.signatureKey = newAuthKey;
    server.verificationKey = newAuthKey;
    respond();
  });
};

describe('integration tests', function () {
  before('run the server before start', function (done) {
    server = socketClusterServer.listen(PORT, serverOptions);
    server.on('connection', connectionHandler);

    server.addMiddleware(server.MIDDLEWARE_AUTHENTICATE, function (req, next) {
      if (req.authToken.username == 'alice') {
        var err = new Error('Blocked by MIDDLEWARE_AUTHENTICATE');
        err.name = 'AuthenticateMiddlewareError';
        next(err);
      } else {
        next();
      }
    });

    server.on('ready', function () {
      done();
    });
  });

  after('shut down server afterwards', function (done) {
    server.close();
    done();
  });

  afterEach('shut down client after each test', function (done) {
    if (client && client.state != client.CLOSED) {
      client.once('disconnect', function () {
        done();
      });
      client.once('connectAbort', function () {
        done();
      });
      client.disconnect();
    } else {
      done();
    }
  });

  describe('authentication', function () {
    it('should not send back error if JWT is not provided in handshake', function (done) {
      client = socketCluster.connect(clientOptions);
      client.once('connect', function (status) {
        assert.equal(status.authError === undefined, true);
        done();
      });
    });

    it('should be authenticated on connect if previous JWT token is present', function (done) {
      client = socketCluster.connect(clientOptions);
      client.once('connect', function (statusA) {
        client.emit('login', {username: 'bob'});
        client.once('authenticate', function (state) {
          assert.equal(client.authState, 'authenticated');

          client.once('disconnect', function () {
            client.once('connect', function (statusB) {
              assert.equal(statusB.isAuthenticated, true);
              assert.equal(statusB.authError === undefined, true);
              done();
            });

            client.connect();
          });

          client.disconnect();
        });
      });
    });

    it('should send back error if JWT is invalid during handshake', function (done) {
      client = socketCluster.connect(clientOptions);
      client.once('connect', function (statusA) {
        // Change the setAuthKey to invalidate the current token.
        client.emit('setAuthKey', 'differentAuthKey', function (err) {
          assert.equal(err == null, true);

          client.once('disconnect', function () {
            client.once('connect', function (statusB) {
              assert.equal(statusB.isAuthenticated, false);
              assert.notEqual(statusB.authError, null);
              assert.equal(statusB.authError.name, 'AuthTokenInvalidError');
              done();
            });

            client.connect();
          });

          client.disconnect();
        });
      });
    });

    it('should allow switching between users', function (done) {
      client = socketCluster.connect(clientOptions);
      client.once('connect', function (statusA) {
        client.emit('login', {username: 'alice'});

        client.once('authTokenChange', function (signedToken) {
          assert.equal(client.authState, 'authenticated');
          assert.notEqual(client.authToken, null);
          assert.equal(client.authToken.username, 'alice');

          done();
        });
      });
    });

    it('should not authenticate the client if MIDDLEWARE_AUTHENTICATE blocks the authentication', function (done) {
      client = socketCluster.connect(clientOptions);
      // The previous test authenticated us as 'alice', so that token will be passed to the server as
      // part of the handshake.
      client.once('connect', function (statusB) {
        // Any token containing the username 'alice' should be blocked by the MIDDLEWARE_AUTHENTICATE middleware.
        // This will only affects token-based authentication, not the credentials-based login event.
        assert.equal(statusB.isAuthenticated, false);
        assert.notEqual(statusB.authError, null);
        assert.equal(statusB.authError.name, 'AuthenticateMiddlewareError');
        done();
      });
    });

    it('token should be available inside login callback if token engine signing is synchronous', function (done) {
      var port = 8009;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authSignAsync: false
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.emit('login', {username: 'bob'}, function (err) {
            assert.equal(client.authState, 'authenticated');
            assert.notEqual(client.authToken, null);
            assert.equal(client.authToken.username, 'bob');
            done();
          });
        });
      });
    });

    it('if token engine signing is asynchronous, authentication can be captured using the authenticate event', function (done) {
      var port = 8010;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authSignAsync: true
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.emit('login', {username: 'bob'});
          client.on('authenticate', function (newSignedToken) {
            assert.equal(client.authState, 'authenticated');
            assert.notEqual(client.authToken, null);
            assert.equal(client.authToken.username, 'bob');
            done();
          });
        });
      });
    });

    it('should still work if token verification is asynchronous', function (done) {
      var port = 8011;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authVerifyAsync: false
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.emit('login', {username: 'bob'});
          client.once('authenticate', function (newSignedToken) {
            client.once('disconnect', function () {
              client.once('connect', function (statusB) {
                assert.equal(statusB.isAuthenticated, true);
                assert.notEqual(client.authToken, null);
                assert.equal(client.authToken.username, 'bob');
                done();
              });
              client.connect();
            });
            client.disconnect();
          });
        });
      });
    });

    it('should set the correct expiry when using expiresIn option when creating a JWT with socket.setAuthToken', function (done) {
      var port = 8012;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authVerifyAsync: false
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.once('authenticate', function (newSignedToken) {
            assert.notEqual(client.authToken, null);
            assert.notEqual(client.authToken.exp, null);
            var dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
            var dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
            // Expiry must be accurate within 1000 milliseconds.
            assert.equal(dateDifference < 1000, true);
            done();
          });
          client.emit('loginWithTenDayExpiry', {username: 'bob'});
        });
      });
    });

    it('should set the correct expiry when adding exp claim when creating a JWT with socket.setAuthToken', function (done) {
      var port = 8013;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authVerifyAsync: false
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.once('authenticate', function (newSignedToken) {
            assert.notEqual(client.authToken, null);
            assert.notEqual(client.authToken.exp, null);
            var dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
            var dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
            // Expiry must be accurate within 1000 milliseconds.
            assert.equal(dateDifference < 1000, true);
            done();
          });
          client.emit('loginWithTenDayExp', {username: 'bob'});
        });
      });
    });

    it('exp claim should have priority over expiresIn option when using socket.setAuthToken', function (done) {
      var port = 8014;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authVerifyAsync: false
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.once('authenticate', function (newSignedToken) {
            assert.notEqual(client.authToken, null);
            assert.notEqual(client.authToken.exp, null);
            var dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
            var dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
            // Expiry must be accurate within 1000 milliseconds.
            assert.equal(dateDifference < 1000, true);
            done();
          });
          client.emit('loginWithTenDayExpAndExpiry', {username: 'bob'});
        });
      });
    });

    it('Should send back error if socket.setAuthToken tries to set both iss claim and issuer option', function (done) {
      var port = 8015;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey,
        authVerifyAsync: false
      });
      var warningMap = {};

      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        client.once('connect', function (statusA) {
          client.once('authenticate', function (newSignedToken) {
            throw new Error('Should not pass authentication because the signature should fail');
          });
          server.on('warning', function (warning) {
            assert.notEqual(warning, null);
            warningMap[warning.name] = warning;
          });
          client.once('error', function (err) {
            assert.notEqual(err, null);
            assert.equal(err.name, 'SocketProtocolError');
          });
          client.emit('loginWithIssAndIssuer', {username: 'bob'});
          setTimeout(function () {
            server.removeAllListeners('warning');
            assert.notEqual(warningMap['SocketProtocolError'], null);
            done();
          }, 1000);
        });
      });
    });
  });

  describe('Event flow', function () {
    it('Should support subscription batching', function (done) {
      var port = 8016;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.on('connection', function (socket) {
        connectionHandler(socket);
        var isFirstMessage = true;
        socket.on('message', function (rawMessage) {
          if (isFirstMessage) {
            var data = JSON.parse(rawMessage);
            // All 20 subscriptions should arrive as a single message.
            assert.equal(data.length, 20);
            isFirstMessage = false;
          }
        });
      });

      var subscribeMiddlewareCounter = 0;
      // Each subscription should pass through the middleware individually, even
      // though they were sent as a batch/array.
      server.addMiddleware(server.MIDDLEWARE_SUBSCRIBE, function (req, next) {
        subscribeMiddlewareCounter++;
        assert.equal(req.channel.indexOf('my-channel-'), 0);
        if (req.channel == 'my-channel-10') {
          assert.equal(JSON.stringify(req.data), JSON.stringify({foo: 123}));
        } else if (req.channel == 'my-channel-12') {
          // Block my-channel-12
          var err = new Error('You cannot subscribe to channel 12');
          err.name = 'UnauthorizedSubscribeError';
          next(err);
          return;
        }
        next();
      });

      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        var channelList = [];
        for (var i = 0; i < 20; i++) {
          var subscribeOptions = {
            batch: true
          };
          if (i == 10) {
            subscribeOptions.data = {foo: 123};
          }
          channelList.push(
            client.subscribe('my-channel-' + i, subscribeOptions)
          );
        }
        channelList[12].on('subscribe', function (err) {
          throw new Error('The my-channel-12 channel should have been blocked by MIDDLEWARE_SUBSCRIBE');
        });
        channelList[12].on('subscribeFail', function (err) {
          assert.notEqual(err, null);
          assert.equal(err.name, 'UnauthorizedSubscribeError');
        });
        channelList[19].watch(function (data) {
          assert.equal(data, 'Hello!');
          assert.equal(subscribeMiddlewareCounter, 20);
          done();
        });
        channelList[0].on('subscribe', function () {
          client.publish('my-channel-19', 'Hello!');
        });
      });
    });

    it('should remove client data from the server when client disconnects before authentication process finished', function (done) {
      var port = 8017;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 500)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });
        var serverSocket;
        server.on('handshake', function (socket) {
          serverSocket = socket;
        });
        setTimeout(function () {
          assert.equal(server.clientsCount, 0);
          assert.equal(server.pendingClientsCount, 1);
          assert.notEqual(serverSocket, null);
          assert.equal(Object.keys(server.pendingClients)[0], serverSocket.id);
          client.disconnect();
        }, 100);
        setTimeout(function () {
          assert.equal(Object.keys(server.clients).length, 0);
          assert.equal(server.clientsCount, 0);
          assert.equal(server.pendingClientsCount, 0);
          assert.equal(JSON.stringify(server.pendingClients), '{}');
          done();
        }, 1000);
      });
    });

    it('Client should not be able to subscribe to a channel before the handshake has completed', function (done) {
      var port = 8018;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 500)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var isSubscribed = false;
        var error;

        server.on('subscription', function (socket, channel) {
          isSubscribed = true;
        });

        // Hack to capture the error without relying on the standard client flow.
        client.transport._callbackMap[2] = {
          event: '#subscribe',
          data: {"channel":"someChannel"},
          callback: function (err) {
            error = err;
          }
        };

        // Trick the server by sending a fake subscribe before the handshake is done.
        client.transport.socket.on('open', function () {
          client.send('{"event":"#subscribe","data":{"channel":"someChannel"},"cid":2}');
        });

        setTimeout(function () {
          assert.equal(isSubscribed, false);
          assert.notEqual(error, null);
          assert.equal(error.name, 'InvalidActionError');
          done();
        }, 1000);
      });
    });

    it('Server-side socket disconnect event should not trigger if the socket did not complete the handshake; instead, it should trigger connectAbort', function (done) {
      var port = 8019;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 500)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var socketDisconnected = false;
        var socketDisconnectedBeforeConnect = false;
        var clientSocketAborted = false;

        var connectionOnServer = false;

        server.once('connection', function () {
          connectionOnServer = true;
        });

        server.once('handshake', function (socket) {
          assert.equal(server.pendingClientsCount, 1);
          assert.notEqual(server.pendingClients[socket.id], null);
          socket.once('disconnect', function () {
            if (!connectionOnServer) {
              socketDisconnectedBeforeConnect = true;
            }
            socketDisconnected = true;
          });
          socket.once('connectAbort', function () {
            clientSocketAborted = true;
          });
        });

        var serverDisconnected = false;
        var serverSocketAborted = false;

        server.once('disconnection', function () {
          serverDisconnected = true;
        });

        server.once('connectionAbort', function () {
          serverSocketAborted = true;
        });

        setTimeout(function () {
          client.disconnect();
        }, 100);
        setTimeout(function () {
          assert.equal(socketDisconnected, false);
          assert.equal(socketDisconnectedBeforeConnect, false);
          assert.equal(clientSocketAborted, true);
          assert.equal(serverSocketAborted, true);
          assert.equal(serverDisconnected, false);
          done();
        }, 1000);
      });
    });

    it('Server-side socket disconnect event should trigger if the socket completed the handshake (not connectAbort)', function (done) {
      var port = 8020;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 10)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var socketDisconnected = false;
        var socketDisconnectedBeforeConnect = false;
        var clientSocketAborted = false;

        var connectionOnServer = false;

        server.once('connection', function () {
          connectionOnServer = true;
        });

        server.once('handshake', function (socket) {
          assert.equal(server.pendingClientsCount, 1);
          assert.notEqual(server.pendingClients[socket.id], null);
          socket.once('disconnect', function () {
            if (!connectionOnServer) {
              socketDisconnectedBeforeConnect = true;
            }
            socketDisconnected = true;
          });
          socket.once('connectAbort', function () {
            clientSocketAborted = true;
          });
        });

        var serverDisconnected = false;
        var serverSocketAborted = false;

        server.once('disconnection', function () {
          serverDisconnected = true;
        });

        server.once('connectionAbort', function () {
          serverSocketAborted = true;
        });

        setTimeout(function () {
          client.disconnect();
        }, 200);
        setTimeout(function () {
          assert.equal(socketDisconnectedBeforeConnect, false);
          assert.equal(socketDisconnected, true);
          assert.equal(clientSocketAborted, false);
          assert.equal(serverDisconnected, true);
          assert.equal(serverSocketAborted, false);
          done();
        }, 1000);
      });
    });

    it('Server-side socket connect event and server connection event should trigger', function (done) {
      var port = 8021;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });

      var connectionEmitted = false;
      var connectionStatus;

      server.on('connection', connectionHandler);
      server.once('connection', function (socket, status) {
        connectionEmitted = true;
        connectionStatus = status;
        // Modify the status object and make sure that it doesn't get modified
        // on the client.
        status.foo = 123;
      });
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var connectEmitted = false;
        var _connectEmitted = false;
        var connectStatus;
        var socketId;

        server.once('handshake', function (socket) {
          socket.once('connect', function (status) {
            socketId = socket.id;
            connectEmitted = true;
            connectStatus = status;
          });
          socket.once('_connect', function () {
            _connectEmitted = true;
          });
        });

        var clientConnectEmitted = false;
        var clientConnectStatus = false;

        client.once('connect', function (status) {
          clientConnectEmitted = true;
          clientConnectStatus = status;
        });

        setTimeout(function () {
          assert.equal(connectEmitted, true);
          assert.equal(_connectEmitted, true);
          assert.equal(connectionEmitted, true);
          assert.equal(clientConnectEmitted, true);

          assert.notEqual(connectionStatus, null);
          assert.equal(connectionStatus.id, socketId);
          assert.equal(connectionStatus.pingTimeout, server.pingTimeout);
          assert.equal(connectionStatus.authError, null);
          assert.equal(connectionStatus.isAuthenticated, false);

          assert.notEqual(connectStatus, null);
          assert.equal(connectStatus.id, socketId);
          assert.equal(connectStatus.pingTimeout, server.pingTimeout);
          assert.equal(connectStatus.authError, null);
          assert.equal(connectStatus.isAuthenticated, false);

          assert.notEqual(clientConnectStatus, null);
          assert.equal(clientConnectStatus.id, socketId);
          assert.equal(clientConnectStatus.pingTimeout, server.pingTimeout);
          assert.equal(clientConnectStatus.authError, null);
          assert.equal(clientConnectStatus.isAuthenticated, false);
          assert.equal(clientConnectStatus.foo, null);
          // Client socket status should be a clone of server socket status; not
          // a reference to the same object.
          assert.notEqual(clientConnectStatus.foo, connectStatus.foo);

          done();
        }, 300);
      });
    });

    it('The close event should trigger when the socket loses the connection before the handshake', function (done) {
      var port = 8022;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 500)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var serverSocketClosed = false;
        var serverSocketAborted = false;
        var serverClosure = false;

        server.on('handshake', function (socket) {
          socket.once('close', function () {
            serverSocketClosed = true;
          });
        });

        server.once('connectionAbort', function () {
          serverSocketAborted = true;
        });

        server.on('closure', function (socket) {
          assert.equal(socket.state, socket.CLOSED);
          serverClosure = true;
        });

        setTimeout(function () {
          client.disconnect();
        }, 100);
        setTimeout(function () {
          assert.equal(serverSocketClosed, true);
          assert.equal(serverSocketAborted, true);
          assert.equal(serverClosure, true);
          done();
        }, 1000);
      });
    });

    it('The close event should trigger when the socket loses the connection after the handshake', function (done) {
      var port = 8023;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });
      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, defaultVerificationOptions, callback) {
          setTimeout(function () {
            callback(null, {})
          }, 0)
        }
      });
      server.on('connection', connectionHandler);
      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var serverSocketClosed = false;
        var serverSocketDisconnected = false;
        var serverClosure = false;

        server.on('handshake', function (socket) {
          socket.once('close', function () {
            serverSocketClosed = true;
          });
        });

        server.once('disconnection', function () {
          serverSocketDisconnected = true;
        });

        server.on('closure', function (socket) {
          assert.equal(socket.state, socket.CLOSED);
          serverClosure = true;
        });

        setTimeout(function () {
          client.disconnect();
        }, 100);
        setTimeout(function () {
          assert.equal(serverSocketClosed, true);
          assert.equal(serverSocketDisconnected, true);
          assert.equal(serverClosure, true);
          done();
        }, 300);
      });
    });

    it('Exchange is attached to socket before the handshake event is triggered', function (done) {
      var port = 8024;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });

      server.on('connection', connectionHandler);

      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        server.once('handshake', function (socket) {
          assert.notEqual(socket.exchange, null);
        });

        setTimeout(function () {
          done();
        }, 300);
      });
    });

    it('Server should be able to handle invalid #subscribe and #unsubscribe and #publish packets without crashing', function (done) {
      var port = 8025;
      server = socketClusterServer.listen(port, {
        authKey: serverOptions.authKey
      });

      server.on('connection', connectionHandler);

      server.on('ready', function () {
        client = socketCluster.connect({
          hostname: clientOptions.hostname,
          port: port,
          multiplex: false
        });

        var nullInChannelArrayError;
        var objectAsChannelNameError;
        var nullChannelNameError;
        var nullUnsubscribeError;

        var undefinedPublishError;
        var objectAsChannelNamePublishError;
        var nullPublishError;

        // Hacks to capture the errors without relying on the standard client flow.
        client.transport._callbackMap[2] = {
          event: '#subscribe',
          data: [null],
          callback: function (err) {
            nullInChannelArrayError = err;
          }
        };
        client.transport._callbackMap[3] = {
          event: '#subscribe',
          data: {"channel": {"hello": 123}},
          callback: function (err) {
            objectAsChannelNameError = err;
          }
        };
        client.transport._callbackMap[4] = {
          event: '#subscribe',
          data: null,
          callback: function (err) {
            nullChannelNameError = err;
          }
        };
        client.transport._callbackMap[5] = {
          event: '#unsubscribe',
          data: [null],
          callback: function (err) {
            nullUnsubscribeError = err;
          }
        };
        client.transport._callbackMap[6] = {
          event: '#publish',
          data: null,
          callback: function (err) {
            undefinedPublishError = err;
          }
        };
        client.transport._callbackMap[7] = {
          event: '#publish',
          data: {"channel": {"hello": 123}},
          callback: function (err) {
            objectAsChannelNamePublishError = err;
          }
        };
        client.transport._callbackMap[8] = {
          event: '#publish',
          data: {"channel": null},
          callback: function (err) {
            nullPublishError = err;
          }
        };

        // Trick the server by sending a fake subscribe before the handshake is done.
        client.on('connect', function () {
          client.send('{"event":"#subscribe","data":[null],"cid":2}');
          client.send('{"event":"#subscribe","data":{"channel":{"hello":123}},"cid":3}');
          client.send('{"event":"#subscribe","data":null,"cid":4}');
          client.send('{"event":"#unsubscribe","data":[null],"cid":5}');
          client.send('{"event":"#publish","data":null,"cid":6}');
          client.send('{"event":"#publish","data":{"channel":{"hello":123}},"cid":7}');
          client.send('{"event":"#publish","data":{"channel":null},"cid":8}');
        });

        setTimeout(function () {
          assert.notEqual(nullInChannelArrayError, null);
          // console.log('nullInChannelArrayError:', nullInChannelArrayError);
          assert.notEqual(objectAsChannelNameError, null);
          // console.log('objectAsChannelNameError:', objectAsChannelNameError);
          assert.notEqual(nullChannelNameError, null);
          // console.log('nullChannelNameError:', nullChannelNameError);
          assert.notEqual(nullUnsubscribeError, null);
          // console.log('nullUnsubscribeError:', nullUnsubscribeError);
          assert.notEqual(undefinedPublishError, null);
          // console.log('undefinedPublishError:', undefinedPublishError);
          assert.notEqual(objectAsChannelNamePublishError, null);
          // console.log('objectAsChannelNamePublishError:', objectAsChannelNamePublishError);
          assert.notEqual(nullPublishError, null);
          // console.log('nullPublishError:', nullPublishError);

          done();
        }, 300);
      });
    });
  });
});
