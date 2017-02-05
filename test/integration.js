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

var server, client;

describe('integration tests', function () {
  before('run the server before start', function (done) {
    server = socketClusterServer.listen(PORT, serverOptions);
    server.on('connection', function (socket) {
      socket.on('login', function (userDetails, respond) {
        if (userDetails.username == 'bob') {
          socket.setAuthToken({
            username: 'bob'
          });
          respond();
        } else {
          var err = new Error();
          err.name = 'FailedLoginError';
          respond(err);
        }
      });
      socket.on('setAuthKey', function (newAuthKey, respond) {
        server.signatureKey = newAuthKey;
        server.verificationKey = newAuthKey;
        respond();
      });
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
    if (client) {
      client.once('disconnect', function () {
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

    it('should be authenticated on connect if pervious JWT token is present', function (done) {
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

    it('should be send back error if JWT is invalid during handshake', function (done) {
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
  });
});
