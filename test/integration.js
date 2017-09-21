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
        done()
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
  });
});
