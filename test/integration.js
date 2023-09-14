const assert = require('assert');
const socketClusterServer = require('../');
const AGAction = require('../action');
const socketClusterClient = require('socketcluster-client');
const localStorage = require('localStorage');
const AGSimpleBroker = require('ag-simple-broker');

// Add to the global scope like in browser.
global.localStorage = localStorage;

let clientOptions;
let serverOptions;

let allowedUsers = {
  bob: true,
  alice: true
};

const PORT_NUMBER = 8008;
const WS_ENGINE = 'ws';
const LOG_WARNINGS = false;
const LOG_ERRORS = false;

const TEN_DAYS_IN_SECONDS = 60 * 60 * 24 * 10;

let validSignedAuthTokenBob = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJvYiIsImV4cCI6MzE2Mzc1ODk3OTA4MDMxMCwiaWF0IjoxNTAyNzQ3NzQ2fQ.dSZOfsImq4AvCu-Or3Fcmo7JNv1hrV3WqxaiSKkTtAo';
let validSignedAuthTokenAlice = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwiaWF0IjoxNTE4NzI4MjU5LCJleHAiOjMxNjM3NTg5NzkwODAzMTB9.XxbzPPnnXrJfZrS0FJwb_EAhIu2VY5i7rGyUThtNLh4';
let invalidSignedAuthToken = 'fakebGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakec2VybmFtZSI6ImJvYiIsImlhdCI6MTUwMjYyNTIxMywiZXhwIjoxNTAyNzExNjEzfQ.fakemYcOOjM9bzmS4UYRvlWSk_lm3WGHvclmFjLbyOk';

let server, client;

function wait(duration) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve();
    }, duration);
  });
}

async function resolveAfterTimeout(duration, value) {
  await wait(duration);
  return value;
};

function connectionHandler(socket) {
  (async () => {
    for await (let rpc of socket.procedure('login')) {
      if (rpc.data && allowedUsers[rpc.data.username]) {
        socket.setAuthToken(rpc.data);
        rpc.end();
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        rpc.error(err);
      }
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('loginWithTenDayExpiry')) {
      if (allowedUsers[rpc.data.username]) {
        socket.setAuthToken(rpc.data, {
          expiresIn: TEN_DAYS_IN_SECONDS
        });
        rpc.end();
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        rpc.error(err);
      }
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('loginWithTenDayExp')) {
      if (allowedUsers[rpc.data.username]) {
        rpc.data.exp = Math.round(Date.now() / 1000) + TEN_DAYS_IN_SECONDS;
        socket.setAuthToken(rpc.data);
        rpc.end();
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        rpc.error(err);
      }
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('loginWithTenDayExpAndExpiry')) {
      if (allowedUsers[rpc.data.username]) {
        rpc.data.exp = Math.round(Date.now() / 1000) + TEN_DAYS_IN_SECONDS;
        socket.setAuthToken(rpc.data, {
          expiresIn: TEN_DAYS_IN_SECONDS * 100 // 1000 days
        });
        rpc.end();
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        rpc.error(err);
      }
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('loginWithIssAndIssuer')) {
      if (allowedUsers[rpc.data.username]) {
        rpc.data.iss = 'foo';
        try {
          await socket.setAuthToken(rpc.data, {
            issuer: 'bar'
          });
        } catch (err) {}
        rpc.end();
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        rpc.error(err);
      }
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('setAuthKey')) {
      server.signatureKey = rpc.data;
      server.verificationKey = rpc.data;
      rpc.end();
    }
  })();

  (async () => {
    for await (let rpc of socket.procedure('proc')) {
      rpc.end('success ' + rpc.data);
    }
  })();
};

function bindFailureHandlers(server) {
  if (LOG_ERRORS) {
    (async () => {
      for await (let {error} of server.listener('error')) {
        console.error('ERROR', error);
      }
    })();
  }
  if (LOG_WARNINGS) {
    (async () => {
      for await (let {warning} of server.listener('warning')) {
        console.warn('WARNING', warning);
      }
    })();
  }
}

describe('Integration tests', function () {
  beforeEach('Prepare options', async function () {
    clientOptions = {
      hostname: '127.0.0.1',
      port: PORT_NUMBER
    };
    serverOptions = {
      authKey: 'testkey',
      wsEngine: WS_ENGINE
    };
  });

  afterEach('Close server and client after each test', async function () {
    if (client) {
      client.closeAllListeners();
      client.disconnect();
    }
    if (server) {
      server.closeAllListeners();
      server.httpServer.close();
      await server.close();
    }
    global.localStorage.removeItem('socketcluster.authToken');
  });

  describe('Client authentication', function () {
    beforeEach('Run the server before start', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, serverOptions);
      bindFailureHandlers(server);

      server.setMiddleware(server.MIDDLEWARE_INBOUND, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          if (
            action.type === AGAction.AUTHENTICATE &&
            (!action.authToken || action.authToken.username === 'alice')
          ) {
            let err = new Error('Blocked by MIDDLEWARE_INBOUND');
            err.name = 'AuthenticateMiddlewareError';
            action.block(err);
            continue;
          }
          action.allow();
        }
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();
    });

    it('Should not send back error if JWT is not provided in handshake', async function () {
      client = socketClusterClient.create(clientOptions);
      let event = await client.listener('connect').once();
      assert.equal(event.authError === undefined, true);
    });

    it('Should be authenticated on connect if previous JWT token is present', async function () {
      client = socketClusterClient.create(clientOptions);
      await client.listener('connect').once();
      client.invoke('login', {username: 'bob'});
      await client.listener('authenticate').once();
      assert.equal(client.authState, 'authenticated');
      client.disconnect();
      client.connect();
      let event = await client.listener('connect').once();
      assert.equal(event.isAuthenticated, true);
      assert.equal(event.authError === undefined, true);
    });

    it('Should send back error if JWT is invalid during handshake', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      client = socketClusterClient.create(clientOptions);

      await client.listener('connect').once();
      // Change the setAuthKey to invalidate the current token.
      await client.invoke('setAuthKey', 'differentAuthKey');
      client.disconnect();
      client.connect();
      let event = await client.listener('connect').once();
      assert.equal(event.isAuthenticated, false);
      assert.notEqual(event.authError, null);
      assert.equal(event.authError.name, 'AuthTokenInvalidError');
    });

    it('Should allow switching between users', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      let authenticateEvents = [];
      let deauthenticateEvents = [];
      let authenticationStateChangeEvents = [];
      let authStateChangeEvents = [];

      (async () => {
        for await (let stateChangePacket of server.listener('authenticationStateChange')) {
          authenticationStateChangeEvents.push(stateChangePacket);
        }
      })();

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let {authToken} of socket.listener('authenticate')) {
              authenticateEvents.push(authToken);
            }
          })();
          (async () => {
            for await (let {oldAuthToken} of socket.listener('deauthenticate')) {
              deauthenticateEvents.push(oldAuthToken);
            }
          })();
          (async () => {
            for await (let stateChangeData of socket.listener('authStateChange')) {
              authStateChangeEvents.push(stateChangeData);
            }
          })();
        }
      })();

      let clientSocketId;
      client = socketClusterClient.create(clientOptions);
      await client.listener('connect').once();
      clientSocketId = client.id;
      client.invoke('login', {username: 'alice'});

      await wait(100);

      assert.equal(deauthenticateEvents.length, 0);
      assert.equal(authenticateEvents.length, 2);
      assert.equal(authenticateEvents[0].username, 'bob');
      assert.equal(authenticateEvents[1].username, 'alice');

      assert.equal(authenticationStateChangeEvents.length, 1);
      assert.notEqual(authenticationStateChangeEvents[0].socket, null);
      assert.equal(authenticationStateChangeEvents[0].socket.id, clientSocketId);
      assert.equal(authenticationStateChangeEvents[0].oldAuthState, 'unauthenticated');
      assert.equal(authenticationStateChangeEvents[0].newAuthState, 'authenticated');
      assert.notEqual(authenticationStateChangeEvents[0].authToken, null);
      assert.equal(authenticationStateChangeEvents[0].authToken.username, 'bob');

      assert.equal(authStateChangeEvents.length, 1);
      assert.equal(authStateChangeEvents[0].oldAuthState, 'unauthenticated');
      assert.equal(authStateChangeEvents[0].newAuthState, 'authenticated');
      assert.notEqual(authStateChangeEvents[0].authToken, null);
      assert.equal(authStateChangeEvents[0].authToken.username, 'bob');
    });

    it('Should emit correct events/data when socket is deauthenticated', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      let authenticationStateChangeEvents = [];
      let authStateChangeEvents = [];

      (async () => {
        for await (let stateChangePacket of server.listener('authenticationStateChange')) {
          authenticationStateChangeEvents.push(stateChangePacket);
        }
      })();

      client = socketClusterClient.create(clientOptions);

      (async () => {
        for await (let event of client.listener('connect')) {
          client.deauthenticate();
        }
      })();

      let {socket} = await server.listener('connection').once();
      let initialAuthToken = socket.authToken;

      (async () => {
        for await (let stateChangeData of socket.listener('authStateChange')) {
          authStateChangeEvents.push(stateChangeData);
        }
      })();

      let {oldAuthToken} = await socket.listener('deauthenticate').once();
      assert.equal(oldAuthToken, initialAuthToken);

      assert.equal(authStateChangeEvents.length, 2);
      assert.equal(authStateChangeEvents[0].oldAuthState, 'unauthenticated');
      assert.equal(authStateChangeEvents[0].newAuthState, 'authenticated');
      assert.notEqual(authStateChangeEvents[0].authToken, null);
      assert.equal(authStateChangeEvents[0].authToken.username, 'bob');
      assert.equal(authStateChangeEvents[1].oldAuthState, 'authenticated');
      assert.equal(authStateChangeEvents[1].newAuthState, 'unauthenticated');
      assert.equal(authStateChangeEvents[1].authToken, null);

      assert.equal(authenticationStateChangeEvents.length, 2);
      assert.notEqual(authenticationStateChangeEvents[0], null);
      assert.equal(authenticationStateChangeEvents[0].oldAuthState, 'unauthenticated');
      assert.equal(authenticationStateChangeEvents[0].newAuthState, 'authenticated');
      assert.notEqual(authenticationStateChangeEvents[0].authToken, null);
      assert.equal(authenticationStateChangeEvents[0].authToken.username, 'bob');
      assert.notEqual(authenticationStateChangeEvents[1], null);
      assert.equal(authenticationStateChangeEvents[1].oldAuthState, 'authenticated');
      assert.equal(authenticationStateChangeEvents[1].newAuthState, 'unauthenticated');
      assert.equal(authenticationStateChangeEvents[1].authToken, null);
    });

    it('Should throw error if server socket deauthenticate is called after client disconnected and rejectOnFailedDelivery is true', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      client = socketClusterClient.create(clientOptions);

      let {socket} = await server.listener('connection').once();

      client.disconnect();
      let error;
      try {
        await socket.deauthenticate({rejectOnFailedDelivery: true});
      } catch (err) {
        error = err;
      }
      assert.notEqual(error, null);
      assert.equal(error.name, 'BadConnectionError');
    });

    it('Should not throw error if server socket deauthenticate is called after client disconnected and rejectOnFailedDelivery is not true', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      client = socketClusterClient.create(clientOptions);

      let {socket} = await server.listener('connection').once();

      client.disconnect();
      socket.deauthenticate();
    });

    it('Should not authenticate the client if MIDDLEWARE_INBOUND blocks the authentication', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenAlice);

      client = socketClusterClient.create(clientOptions);
      // The previous test authenticated us as 'alice', so that token will be passed to the server as
      // part of the handshake.
      let event = await client.listener('connect').once();
      // Any token containing the username 'alice' should be blocked by the MIDDLEWARE_INBOUND middleware.
      // This will only affects token-based authentication, not the credentials-based login event.
      assert.equal(event.isAuthenticated, false);
      assert.notEqual(event.authError, null);
      assert.equal(event.authError.name, 'AuthenticateMiddlewareError');
    });
  });

  describe('Server authentication', function () {
    it('Token should be available after the authenticate listener resolves', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      client.invoke('login', {username: 'bob'});
      await client.listener('authenticate').once();

      assert.equal(client.authState, 'authenticated');
      assert.notEqual(client.authToken, null);
      assert.equal(client.authToken.username, 'bob');
    });

    it('Authentication can be captured using the authenticate listener', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      client.invoke('login', {username: 'bob'});
      await client.listener('authenticate').once();

      assert.equal(client.authState, 'authenticated');
      assert.notEqual(client.authToken, null);
      assert.equal(client.authToken.username, 'bob');
    });

    it('Previously authenticated client should still be authenticated after reconnecting', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      client.invoke('login', {username: 'bob'});

      await client.listener('authenticate').once();

      client.disconnect();
      client.connect();

      let event = await client.listener('connect').once();

      assert.equal(event.isAuthenticated, true);
      assert.notEqual(client.authToken, null);
      assert.equal(client.authToken.username, 'bob');
    });

    it('Should set the correct expiry when using expiresIn option when creating a JWT with socket.setAuthToken', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();
      client.invoke('loginWithTenDayExpiry', {username: 'bob'});
      await client.listener('authenticate').once();

      assert.notEqual(client.authToken, null);
      assert.notEqual(client.authToken.exp, null);
      let dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
      let dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
      // Expiry must be accurate within 1000 milliseconds.
      assert.equal(dateDifference < 1000, true);
    });

    it('Should set the correct expiry when adding exp claim when creating a JWT with socket.setAuthToken', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();
      client.invoke('loginWithTenDayExp', {username: 'bob'});
      await client.listener('authenticate').once();

      assert.notEqual(client.authToken, null);
      assert.notEqual(client.authToken.exp, null);
      let dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
      let dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
      // Expiry must be accurate within 1000 milliseconds.
      assert.equal(dateDifference < 1000, true);
    });

    it('The exp claim should have priority over expiresIn option when using socket.setAuthToken', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();
      client.invoke('loginWithTenDayExpAndExpiry', {username: 'bob'});
      await client.listener('authenticate').once();

      assert.notEqual(client.authToken, null);
      assert.notEqual(client.authToken.exp, null);
      let dateMillisecondsInTenDays = Date.now() + TEN_DAYS_IN_SECONDS * 1000;
      let dateDifference = Math.abs(dateMillisecondsInTenDays - client.authToken.exp * 1000);
      // Expiry must be accurate within 1000 milliseconds.
      assert.equal(dateDifference < 1000, true);
    });

    it('Should send back error if socket.setAuthToken tries to set both iss claim and issuer option', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let warningMap = {};

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      (async () => {
        await client.listener('authenticate').once();
        throw new Error('Should not pass authentication because the signature should fail');
      })();

      (async () => {
        for await (let {warning} of server.listener('warning')) {
          assert.notEqual(warning, null);
          warningMap[warning.name] = warning;
        }
      })();

      (async () => {
        for await (let {error} of server.listener('error')) {
          assert.notEqual(error, null);
          assert.equal(error.name, 'SocketProtocolError');
        }
      })();

      let closePackets = [];

      (async () => {
        let event = await client.listener('close').once();
        closePackets.push(event);
      })();

      let error;
      try {
        await client.invoke('loginWithIssAndIssuer', {username: 'bob'});
      } catch (err) {
        error = err;
      }

      assert.notEqual(error, null);
      assert.equal(error.name, 'BadConnectionError');

      await wait(1000);

      assert.equal(closePackets.length, 1);
      assert.equal(closePackets[0].code, 4002);
      server.closeListener('warning');
      assert.notEqual(warningMap['SocketProtocolError'], null);
    });

    it('Should trigger an authTokenSigned event and socket.signedAuthToken should be set after calling the socket.setAuthToken method', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let authTokenSignedEventEmitted = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let {signedAuthToken} of socket.listener('authTokenSigned')) {
              authTokenSignedEventEmitted = true;
              assert.notEqual(signedAuthToken, null);
              assert.equal(signedAuthToken, socket.signedAuthToken);
            }
          })();

          (async () => {
            for await (let req of socket.procedure('login')) {
              if (allowedUsers[req.data.username]) {
                socket.setAuthToken(req.data);
                req.end();
              } else {
                let err = new Error('Failed to login');
                err.name = 'FailedLoginError';
                req.error(err);
              }
            }
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      await Promise.all([
        client.invoke('login', {username: 'bob'}),
        client.listener('authenticate').once()
      ]);

      assert.equal(authTokenSignedEventEmitted, true);
    });

    it('The socket.setAuthToken call should reject if token delivery fails and rejectOnFailedDelivery option is true', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        ackTimeout: 1000
      });
      bindFailureHandlers(server);

      let serverWarnings = [];

      (async () => {
        await server.listener('ready').once();
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });
        await client.listener('connect').once();
        client.invoke('login', {username: 'bob'});
      })();

      let {socket} = await server.listener('connection').once();

      (async () => {
        for await (let {warning} of server.listener('warning')) {
          serverWarnings.push(warning);
        }
      })();

      let req = await socket.procedure('login').once();
      if (allowedUsers[req.data.username]) {
        req.end();
        socket.disconnect();
        let error;
        try {
          await socket.setAuthToken(req.data, {rejectOnFailedDelivery: true});
        } catch (err) {
          error = err;
        }
        assert.notEqual(error, null);
        assert.equal(error.name, 'AuthError');
        await wait(0);
        assert.notEqual(serverWarnings[0], null);
        assert.equal(serverWarnings[0].name, 'BadConnectionError');
        assert.notEqual(serverWarnings[1], null);
        assert.equal(serverWarnings[1].name, 'AuthError');
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        req.error(err);
      }
    });

    it('The socket.setAuthToken call should not reject if token delivery fails and rejectOnFailedDelivery option is not true', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        ackTimeout: 1000
      });
      bindFailureHandlers(server);

      let serverWarnings = [];

      (async () => {
        await server.listener('ready').once();
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });
        await client.listener('connect').once();
        client.invoke('login', {username: 'bob'});
      })();

      let {socket} = await server.listener('connection').once();

      (async () => {
        for await (let {warning} of server.listener('warning')) {
          serverWarnings.push(warning);
        }
      })();

      let req = await socket.procedure('login').once();
      if (allowedUsers[req.data.username]) {
        req.end();
        socket.disconnect();
        let error;
        try {
          await socket.setAuthToken(req.data);
        } catch (err) {
          error = err;
        }
        assert.equal(error, null);
        await wait(0);
        assert.notEqual(serverWarnings[0], null);
        assert.equal(serverWarnings[0].name, 'BadConnectionError');
      } else {
        let err = new Error('Failed to login');
        err.name = 'FailedLoginError';
        req.error(err);
      }
    });

    it('The verifyToken method of the authEngine receives correct params', async function () {
      global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);

      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      (async () => {
        await server.listener('ready').once();
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });
      })();

      return new Promise((resolve) => {
        server.setAuthEngine({
          verifyToken: async (signedAuthToken, verificationKey, verificationOptions) => {
            await wait(500);
            assert.equal(signedAuthToken, validSignedAuthTokenBob);
            assert.equal(verificationKey, serverOptions.authKey);
            assert.notEqual(verificationOptions, null);
            assert.notEqual(verificationOptions.socket, null);
            resolve();
            return Promise.resolve({});
          }
        });
      });
    });

    it('Should remove client data from the server when client disconnects before authentication process finished', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(500, {});
        }
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();
      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let serverSocket;
      (async () => {
        for await (let {socket} of server.listener('handshake')) {
          serverSocket = socket;
        }
      })();

      await wait(100);
      assert.equal(server.clientsCount, 0);
      assert.equal(server.pendingClientsCount, 1);
      assert.notEqual(serverSocket, null);
      assert.equal(Object.keys(server.pendingClients)[0], serverSocket.id);
      client.disconnect();

      await wait(1000);
      assert.equal(Object.keys(server.clients).length, 0);
      assert.equal(server.clientsCount, 0);
      assert.equal(server.pendingClientsCount, 0);
      assert.equal(JSON.stringify(server.pendingClients), '{}');
    });
  });

  describe('Socket handshake', function () {
    it('Exchange is attached to socket before the handshake event is triggered', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let {socket} = await server.listener('handshake').once();
      assert.notEqual(socket.exchange, null);
    });

    it('Should close the connection if the client tries to send a message before the handshake', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      client.transport.socket.onopen = function () {
        client.transport.socket.send(Buffer.alloc(0));
      };

      let results = await Promise.all([
        server.listener('closure').once(200),
        client.listener('close').once(200)
      ]);
      assert.equal(results[0].code, 4009);
      assert.equal(results[0].reason, 'Server received a message before the client handshake');
      assert.equal(results[1].code, 4009);
      assert.equal(results[1].reason, 'Server received a message before the client handshake');
    });

    it('Should close the connection if the client tries to send a ping before the handshake', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      client.transport.socket.onopen = function () {
        client.transport.socket.send('');
      };

      let {code: closeCode} = await client.listener('close').once(200);

      assert.equal(closeCode, 4009);
    });

    it('Should not close the connection if the client tries to send a message before the handshake and strictHandshake is false', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        strictHandshake: false
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let realOnOpenFunction = client.transport.socket.onopen;

      client.transport.socket.onopen = function () {
        client.transport.socket.send(Buffer.alloc(0));
        return realOnOpenFunction.apply(this, arguments);
      };

      let packet = await client.listener('connect').once(200);

      assert.notEqual(packet, null);
      assert.notEqual(packet.id, null);
    });
  });

  describe('Socket connection', function () {
    it('Server-side socket connect event and server connection event should trigger', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let connectionEmitted = false;
      let connectionEvent;

      (async () => {
        for await (let event of server.listener('connection')) {
          connectionEvent = event;
          connectionHandler(event.socket);
          connectionEmitted = true;
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let connectEmitted = false;
      let connectStatus;
      let socketId;

      (async () => {
        for await (let {socket} of server.listener('handshake')) {
          (async () => {
            for await (let serverSocketStatus of socket.listener('connect')) {
              socketId = socket.id;
              connectEmitted = true;
              connectStatus = serverSocketStatus;
              // This is to check that mutating the status on the server
              // doesn't affect the status sent to the client.
              serverSocketStatus.foo = 123;
            }
          })();
        }
      })();

      let clientConnectEmitted = false;
      let clientConnectStatus = false;

      (async () => {
        for await (let event of client.listener('connect')) {
          clientConnectEmitted = true;
          clientConnectStatus = event;
        }
      })();

      await wait(300);

      assert.equal(connectEmitted, true);
      assert.equal(connectionEmitted, true);
      assert.equal(clientConnectEmitted, true);

      assert.notEqual(connectionEvent, null);
      assert.equal(connectionEvent.id, socketId);
      assert.equal(connectionEvent.pingTimeout, server.pingTimeout);
      assert.equal(connectionEvent.authError, null);
      assert.equal(connectionEvent.isAuthenticated, false);

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
    });
  });

  describe('Socket disconnection', function () {
    it('Server-side socket disconnect event should not trigger if the socket did not complete the handshake; instead, it should trigger connectAbort', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(500, {});
        }
      });

      let connectionOnServer = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionOnServer = true;
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let socketDisconnected = false;
      let socketDisconnectedBeforeConnect = false;
      let clientSocketAborted = false;

      (async () => {
        let {socket} = await server.listener('handshake').once();
        assert.equal(server.pendingClientsCount, 1);
        assert.notEqual(server.pendingClients[socket.id], null);

        (async () => {
          await socket.listener('disconnect').once();
          if (!connectionOnServer) {
            socketDisconnectedBeforeConnect = true;
          }
          socketDisconnected = true;
        })();

        (async () => {
          let event = await socket.listener('connectAbort').once();
          clientSocketAborted = true;
          assert.equal(event.code, 4444);
          assert.equal(event.reason, 'Disconnect before handshake');
        })();
      })();

      let serverDisconnected = false;
      let serverSocketAborted = false;

      (async () => {
        await server.listener('disconnection').once();
        serverDisconnected = true;
      })();

      (async () => {
        await server.listener('connectionAbort').once();
        serverSocketAborted = true;
      })();

      await wait(100);
      client.disconnect(4444, 'Disconnect before handshake');

      await wait(1000);
      assert.equal(socketDisconnected, false);
      assert.equal(socketDisconnectedBeforeConnect, false);
      assert.equal(clientSocketAborted, true);
      assert.equal(serverSocketAborted, true);
      assert.equal(serverDisconnected, false);
    });

    it('Server-side socket disconnect event should trigger if the socket completed the handshake (not connectAbort)', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(10, {});
        }
      });

      let connectionOnServer = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionOnServer = true;
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let socketDisconnected = false;
      let socketDisconnectedBeforeConnect = false;
      let clientSocketAborted = false;

      (async () => {
        let {socket} = await server.listener('handshake').once();
        assert.equal(server.pendingClientsCount, 1);
        assert.notEqual(server.pendingClients[socket.id], null);

        (async () => {
          let event = await socket.listener('disconnect').once();
          if (!connectionOnServer) {
            socketDisconnectedBeforeConnect = true;
          }
          socketDisconnected = true;
          assert.equal(event.code, 4445);
          assert.equal(event.reason, 'Disconnect after handshake');
        })();

        (async () => {
          let event = await socket.listener('connectAbort').once();
          clientSocketAborted = true;
        })();
      })();

      let serverDisconnected = false;
      let serverSocketAborted = false;

      (async () => {
        await server.listener('disconnection').once();
        serverDisconnected = true;
      })();

      (async () => {
        await server.listener('connectionAbort').once();
        serverSocketAborted = true;
      })();

      await wait(200);
      client.disconnect(4445, 'Disconnect after handshake');

      await wait(1000);

      assert.equal(socketDisconnectedBeforeConnect, false);
      assert.equal(socketDisconnected, true);
      assert.equal(clientSocketAborted, false);
      assert.equal(serverDisconnected, true);
      assert.equal(serverSocketAborted, false);
    });

    it('The close event should trigger when the socket loses the connection before the handshake', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(500, {});
        }
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionOnServer = true;
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let serverSocketClosed = false;
      let serverSocketAborted = false;
      let serverClosure = false;

      (async () => {
        for await (let {socket} of server.listener('handshake')) {
          let event = await socket.listener('close').once();
          serverSocketClosed = true;
          assert.equal(event.code, 4444);
          assert.equal(event.reason, 'Disconnect before handshake');
        }
      })();

      (async () => {
        for await (let event of server.listener('connectionAbort')) {
          serverSocketAborted = true;
        }
      })();

      (async () => {
        for await (let event of server.listener('closure')) {
          assert.equal(event.socket.state, event.socket.CLOSED);
          serverClosure = true;
        }
      })();

      await wait(100);
      client.disconnect(4444, 'Disconnect before handshake');

      await wait(1000);
      assert.equal(serverSocketClosed, true);
      assert.equal(serverSocketAborted, true);
      assert.equal(serverClosure, true);
    });

    it('The close event should trigger when the socket loses the connection after the handshake', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(0, {});
        }
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionOnServer = true;
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let serverSocketClosed = false;
      let serverDisconnection = false;
      let serverClosure = false;

      (async () => {
        for await (let {socket} of server.listener('handshake')) {
          let event = await socket.listener('close').once();
          serverSocketClosed = true;
          assert.equal(event.code, 4445);
          assert.equal(event.reason, 'Disconnect after handshake');
        }
      })();

      (async () => {
        for await (let event of server.listener('disconnection')) {
          serverDisconnection = true;
        }
      })();

      (async () => {
        for await (let event of server.listener('closure')) {
          assert.equal(event.socket.state, event.socket.CLOSED);
          serverClosure = true;
        }
      })();

      await wait(100);
      client.disconnect(4445, 'Disconnect after handshake');

      await wait(1000);
      assert.equal(serverSocketClosed, true);
      assert.equal(serverDisconnection, true);
      assert.equal(serverClosure, true);
    });

    it('Disconnection should support socket message backpressure', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let serverWarnings = [];
      (async () => {
        for await (let {warning} of server.listener('warning')) {
          serverWarnings.push(warning);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let currentRequestData = null;
      let requestDataAtTimeOfDisconnect = null;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionOnServer = true;
          connectionHandler(socket);

          (async () => {
            await socket.listener('disconnect').once();
            requestDataAtTimeOfDisconnect = currentRequestData;
          })();

          (async () => {
            for await (let request of socket.procedure('foo')) {
              currentRequestData = request.data;
              await wait(10);
              (async () => {
                try {
                  await socket.invoke('bla', request.data);
                } catch (err) {}
              })();
              socket.transmit('hi', request.data);
              request.end('bar');
              if (request.data === 10) {
                client.disconnect();
              }
            }
          })();
        }
      })();

      for (let i = 0; i < 30; i++) {
        (async () => {
          let result;
          try {
            result = await client.invoke('foo', i);
          } catch (error) {
            return;
          }
        })();
      }

      await wait(200);

      // Expect a server warning (socket error) if a response was sent on a disconnected socket.
      assert.equal(
        serverWarnings.some((warning) => {
          return warning.message.match(/WebSocket is not open/g);
        }),
        true
      );

      // Expect a server warning (socket error) if transmit was called on a disconnected socket.
      assert.equal(
        serverWarnings.some((warning) => {
          return warning.name === 'BadConnectionError' && warning.message.match(/Socket transmit hi event was aborted/g);
        }),
        true
      );

      // Expect a server warning (socket error) if invoke was called on a disconnected socket.
      assert.equal(
        serverWarnings.some((warning) => {
          return warning.name === 'BadConnectionError' && warning.message.match(/Socket invoke bla event was aborted/g);
        }),
        true
      );

      // Check that the disconnect event on the back end socket triggers as soon as possible (out-of-band) and not at the end of the stream.
      // Any value less than 30 indicates that the 'disconnect' event was triggerred out-of-band.
      // Since the client disconnect() call is executed on the 11th message, we can assume that the 'disconnect' event will trigger sooner.
      assert.equal(requestDataAtTimeOfDisconnect < 15, true);
    });

    it('Socket streams should be killed immediately if socket disconnects (default/kill mode)', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let handledPackets = [];
      let closedReceiver = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let packet of socket.receiver('foo')) {
              await wait(30);
              handledPackets.push(packet);
            }
            closedReceiver = true;
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await wait(100);

      for (let i = 0; i < 15; i++) {
        client.transmit('foo', i);
      }

      await wait(110);

      client.disconnect(4445, 'Disconnect');

      await wait(500);
      assert.equal(handledPackets.length, 4);
      assert.equal(closedReceiver, true);
    });

    it('Socket streams should be closed eventually if socket disconnects (close mode)', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        socketStreamCleanupMode: 'close'
      });
      bindFailureHandlers(server);

      let handledPackets = [];
      let closedReceiver = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let packet of socket.receiver('foo')) {
              await wait(30);
              handledPackets.push(packet);
            }
            closedReceiver = true;
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await wait(100);

      for (let i = 0; i < 15; i++) {
        client.transmit('foo', i);
      }

      await wait(110);

      client.disconnect(4445, 'Disconnect');

      await wait(500);
      assert.equal(handledPackets.length, 15);
      assert.equal(closedReceiver, true);
    });

    it('Socket streams should be closed eventually if socket disconnects (none mode)', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        socketStreamCleanupMode: 'none'
      });
      bindFailureHandlers(server);

      let handledPackets = [];
      let closedReceiver = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let packet of socket.receiver('foo')) {
              await wait(30);
              handledPackets.push(packet);
            }
            closedReceiver = false;
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await wait(100);

      for (let i = 0; i < 15; i++) {
        client.transmit('foo', i);
      }

      await wait(110);

      client.disconnect(4445, 'Disconnect');

      await wait(500);
      assert.equal(handledPackets.length, 15);
      assert.equal(closedReceiver, false);
    });
  });

  describe('Socket RPC invoke', function () {
    it ('Should support invoking a remote procedure on the server', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let req of socket.procedure('customProc')) {
              if (req.data.bad) {
                let error = new Error('Server failed to execute the procedure');
                error.name = 'BadCustomError';
                req.error(error);
              } else {
                req.end('Success');
              }
            }
          })();
        }
      })();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let result = await client.invoke('customProc', {good: true});
      assert.equal(result, 'Success');

      let error;
      try {
        result = await client.invoke('customProc', {bad: true});
      } catch (err) {
        error = err;
      }
      assert.notEqual(error, null);
      assert.equal(error.name, 'BadCustomError');
    });
  });

  describe('Socket transmit', function () {
    it ('Should support receiving remote transmitted data on the server', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        await wait(10);

        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });

        client.transmit('customRemoteEvent', 'This is data');
      })();

      for await (let {socket} of server.listener('connection')) {
        for await (let data of socket.receiver('customRemoteEvent')) {
          assert.equal(data, 'This is data');
          break;
        }
        break;
      }
    });
  });

  describe('Socket backpressure', function () {
    it('Should be able to getInboundBackpressure() on a socket object', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let backpressureHistory = [];

      server.setMiddleware(server.MIDDLEWARE_INBOUND_RAW, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          backpressureHistory.push(action.socket.getInboundBackpressure());
          action.allow();
        }
      });

      server.setMiddleware(server.MIDDLEWARE_INBOUND, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          if (action.data === 5) {
            await wait(100);
          }
          action.allow();
        }
      });

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();
      for (let i = 0; i < 20; i++) {
        await wait(10);
        client.transmitPublish('foo', i);
      }

      await wait(400);

      // Backpressure should go up and come back down.
      assert.equal(backpressureHistory.length, 21);
      assert.equal(backpressureHistory[0], 1);
      assert.equal(backpressureHistory[12] > 4, true);
      assert.equal(backpressureHistory[14] > 6, true);
      assert.equal(backpressureHistory[19], 1);
    });

    it('Should be able to getOutboundBackpressure() on a socket object', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let backpressureHistory = [];

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            await socket.listener('subscribe').once();

            for (let i = 0; i < 20; i++) {
              await wait(10);
              server.exchange.transmitPublish('foo', i);
              backpressureHistory.push(socket.getOutboundBackpressure());
            }
          })();
        }
      })();

      server.setMiddleware(server.MIDDLEWARE_OUTBOUND, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          if (action.data === 5) {
            await wait(100);
          }
          action.allow();
        }
      });

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.subscribe('foo').listener('subscribe').once();

      await wait(400);

      // Backpressure should go up and come back down.
      assert.equal(backpressureHistory.length, 20);
      assert.equal(backpressureHistory[0], 1);
      assert.equal(backpressureHistory[13] > 7, true);
      assert.equal(backpressureHistory[14] > 8, true);
      assert.equal(backpressureHistory[19], 1);
    });

    it('Should be able to getBackpressure() on a socket object and it should be the highest backpressure', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let backpressureHistory = [];

      server.setMiddleware(server.MIDDLEWARE_INBOUND_RAW, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          backpressureHistory.push(action.socket.getBackpressure());
          action.allow();
        }
      });

      server.setMiddleware(server.MIDDLEWARE_INBOUND, async (middlewareStream) => {
        for await (let action of middlewareStream) {
          if (action.data === 5) {
            await wait(100);
          }
          action.allow();
        }
      });

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();
      for (let i = 0; i < 20; i++) {
        await wait(10);
        client.transmitPublish('foo', i);
      }

      await wait(400);

      // Backpressure should go up and come back down.
      assert.equal(backpressureHistory.length, 21);
      assert.equal(backpressureHistory[0], 1);
      assert.equal(backpressureHistory[12] > 4, true);
      assert.equal(backpressureHistory[14] > 6, true);
      assert.equal(backpressureHistory[19], 1);
    });
  });

  describe('Socket pub/sub', function () {
    it('Should maintain order of publish and subscribe', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      await client.listener('connect').once();

      let receivedMessages = [];

      (async () => {
        for await (let data of client.subscribe('foo')) {
          receivedMessages.push(data);
        }
      })();

      await client.invokePublish('foo', 123);

      assert.equal(client.state, client.OPEN);
      await wait(100);
      assert.equal(receivedMessages.length, 1);
    });

    it('Should maintain order of publish and subscribe when client starts out as disconnected', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER,
        autoConnect: false
      });

      assert.equal(client.state, client.CLOSED);

      let receivedMessages = [];

      (async () => {
        for await (let data of client.subscribe('foo')) {
          receivedMessages.push(data);
        }
      })();

      client.invokePublish('foo', 123);

      await wait(100);
      assert.equal(client.state, client.OPEN);
      assert.equal(receivedMessages.length, 1);
    });

    it('Client should not be able to subscribe to a channel before the handshake has completed', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      server.setAuthEngine({
        verifyToken: function (signedAuthToken, verificationKey, verificationOptions) {
          return resolveAfterTimeout(500, {});
        }
      });

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let isSubscribed = false;
      let error;

      (async () => {
        for await (let event of server.listener('subscription')) {
          isSubscribed = true;
        }
      })();

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

      await wait(1000);
      assert.equal(isSubscribed, false);
      assert.notEqual(error, null);
      assert.equal(error.name, 'BadConnectionError');
    });

    it('Server should be able to handle invalid #subscribe and #unsubscribe and #publish events without crashing', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let nullInChannelArrayError;
      let objectAsChannelNameError;
      let nullChannelNameError;
      let nullUnsubscribeError;

      let undefinedPublishError;
      let objectAsChannelNamePublishError;
      let nullPublishError;

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

      (async () => {
        for await (let event of client.listener('connect')) {
          // Trick the server by sending a fake subscribe before the handshake is done.
          client.send('{"event":"#subscribe","data":[null],"cid":2}');
          client.send('{"event":"#subscribe","data":{"channel":{"hello":123}},"cid":3}');
          client.send('{"event":"#subscribe","data":null,"cid":4}');
          client.send('{"event":"#unsubscribe","data":[null],"cid":5}');
          client.send('{"event":"#publish","data":null,"cid":6}');
          client.send('{"event":"#publish","data":{"channel":{"hello":123}},"cid":7}');
          client.send('{"event":"#publish","data":{"channel":null},"cid":8}');
        }
      })();

      await wait(300);

      assert.notEqual(nullInChannelArrayError, null);
      assert.notEqual(objectAsChannelNameError, null);
      assert.notEqual(nullChannelNameError, null);
      assert.notEqual(nullUnsubscribeError, null);
      assert.notEqual(undefinedPublishError, null);
      assert.notEqual(objectAsChannelNamePublishError, null);
      assert.notEqual(nullPublishError, null);
    });

    it('When default AGSimpleBroker broker engine is used, disconnect event should trigger before unsubscribe event', async function () {
      // Only the case in usabilityMode as there is a performance trade-off.
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        usabilityMode: true
      });
      bindFailureHandlers(server);

      let eventList = [];

      (async () => {
        await server.listener('ready').once();

        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });

        await client.subscribe('foo').listener('subscribe').once();
        await wait(200);
        client.disconnect();
      })();

      let {socket} = await server.listener('connection').once();

      (async () => {
        for await (let event of socket.listener('unsubscribe')) {
          eventList.push({
            type: 'unsubscribe',
            channel: event.channel
          });
        }
      })();

      (async () => {
        for await (let disconnectPacket of socket.listener('disconnect')) {
          eventList.push({
            type: 'disconnect',
            code: disconnectPacket.code,
            reason: disconnectPacket.data
          });
        }
      })();

      await wait(300);
      assert.equal(eventList[0].type, 'disconnect');
      assert.equal(eventList[1].type, 'unsubscribe');
      assert.equal(eventList[1].channel, 'foo');
    });

    it('When default AGSimpleBroker broker engine is used, agServer.exchange should support consuming data from a channel', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      (async () => {
        await client.listener('connect').once();

        client.transmitPublish('foo', 'hi1');
        await wait(10);
        client.transmitPublish('foo', 'hi2');
      })();

      let receivedSubscribedData = [];
      let receivedChannelData = [];

      (async () => {
        let subscription = server.exchange.subscribe('foo');
        for await (let data of subscription) {
          receivedSubscribedData.push(data);
        }
      })();

      let channel = server.exchange.channel('foo');
      for await (let data of channel) {
        receivedChannelData.push(data);
        if (receivedChannelData.length > 1) {
          break;
        }
      }

      assert.equal(server.exchange.isSubscribed('foo'), true);
      assert.equal(server.exchange.subscriptions().join(','), 'foo');

      assert.equal(receivedSubscribedData[0], 'hi1');
      assert.equal(receivedSubscribedData[1], 'hi2');
      assert.equal(receivedChannelData[0], 'hi1');
      assert.equal(receivedChannelData[1], 'hi2');
    });

    it('When default AGSimpleBroker broker engine is used, agServer.exchange should support publishing data to a channel', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      (async () => {
        await client.listener('subscribe').once();
        server.exchange.transmitPublish('bar', 'hello1');
        await wait(10);
        server.exchange.transmitPublish('bar', 'hello2');
      })();

      let receivedSubscribedData = [];
      let receivedChannelData = [];

      (async () => {
        let subscription = client.subscribe('bar');
        for await (let data of subscription) {
          receivedSubscribedData.push(data);
        }
      })();

      let channel = client.channel('bar');
      for await (let data of channel) {
        receivedChannelData.push(data);
        if (receivedChannelData.length > 1) {
          break;
        }
      }

      assert.equal(receivedSubscribedData[0], 'hello1');
      assert.equal(receivedSubscribedData[1], 'hello2');
      assert.equal(receivedChannelData[0], 'hello1');
      assert.equal(receivedChannelData[1], 'hello2');
    });

    it('When disconnecting a socket, the unsubscribe event should trigger after the disconnect and close events', async function () {
      let customBrokerEngine = new AGSimpleBroker();
      let defaultUnsubscribeSocket = customBrokerEngine.unsubscribeSocket;
      customBrokerEngine.unsubscribeSocket = function (socket, channel) {
        return resolveAfterTimeout(100, defaultUnsubscribeSocket.call(this, socket, channel));
      };

      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        brokerEngine: customBrokerEngine
      });
      bindFailureHandlers(server);

      let eventList = [];

      (async () => {
        await server.listener('ready').once();
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });

        for await (let event of client.subscribe('foo').listener('subscribe')) {
          (async () => {
            await wait(200);
            client.disconnect();
          })();
        }
      })();

      let {socket} = await server.listener('connection').once();

      (async () => {
        for await (let event of socket.listener('unsubscribe')) {
          eventList.push({
            type: 'unsubscribe',
            channel: event.channel
          });
        }
      })();

      (async () => {
        for await (let event of socket.listener('disconnect')) {
          eventList.push({
            type: 'disconnect',
            code: event.code,
            reason: event.reason
          });
        }
      })();

      (async () => {
        for await (let event of socket.listener('close')) {
          eventList.push({
            type: 'close',
            code: event.code,
            reason: event.reason
          });
        }
      })();

      await wait(700);
      assert.equal(eventList[0].type, 'disconnect');
      assert.equal(eventList[1].type, 'close');
      assert.equal(eventList[2].type, 'unsubscribe');
      assert.equal(eventList[2].channel, 'foo');
    });

    it('Socket should emit an error when trying to unsubscribe from a channel which it is not subscribed to', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let errorList = [];

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let {error} of socket.listener('error')) {
              errorList.push(error);
            }
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      let error;
      try {
        await client.invoke('#unsubscribe', 'bar');
      } catch (err) {
        error = err;
      }
      assert.notEqual(error, null);
      assert.equal(error.name, 'BrokerError');

      await wait(100);
      assert.equal(errorList.length, 1);
      assert.equal(errorList[0].name, 'BrokerError');
    });

    it('Socket should not receive messages from a channel which it has only just unsubscribed from (accounting for delayed unsubscribe by brokerEngine)', async function () {
      let customBrokerEngine = new AGSimpleBroker();
      let defaultUnsubscribeSocket = customBrokerEngine.unsubscribeSocket;
      customBrokerEngine.unsubscribeSocket = function (socket, channel) {
        return resolveAfterTimeout(300, defaultUnsubscribeSocket.call(this, socket, channel));
      };

      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        brokerEngine: customBrokerEngine
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          (async () => {
            for await (let event of socket.listener('unsubscribe')) {
              if (event.channel === 'foo') {
                server.exchange.transmitPublish('foo', 'hello');
              }
            }
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });
      // Stub the isSubscribed method so that it always returns true.
      // That way the client will always invoke watchers whenever
      // it receives a #publish event.
      client.isSubscribed = function () { return true; };

      let messageList = [];

      let fooChannel = client.subscribe('foo');

      (async () => {
        for await (let data of fooChannel) {
          messageList.push(data);
        }
      })();

      (async () => {
        for await (let event of fooChannel.listener('subscribe')) {
          client.invoke('#unsubscribe', 'foo');
        }
      })();

      await wait(200);
      assert.equal(messageList.length, 0);
    });

    it('Socket channelSubscriptions and channelSubscriptionsCount should update when socket.kickOut(channel) is called', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      let errorList = [];
      let serverSocket;
      let wasKickOutCalled = false;

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          serverSocket = socket;

          (async () => {
            for await (let {error} of socket.listener('error')) {
              errorList.push(error);
            }
          })();

          (async () => {
            for await (let event of socket.listener('subscribe')) {
              if (event.channel === 'foo') {
                await wait(50);
                wasKickOutCalled = true;
                socket.kickOut('foo', 'Socket was kicked out of the channel');
              }
            }
          })();
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER
      });

      client.subscribe('foo');

      await wait(100);
      assert.equal(errorList.length, 0);
      assert.equal(wasKickOutCalled, true);
      assert.equal(serverSocket.channelSubscriptionsCount, 0);
      assert.equal(Object.keys(serverSocket.channelSubscriptions).length, 0);
    });
  });

  describe('Batching', function () {
    it('Should batch messages sent through sockets after the handshake when the batchOnHandshake option is true', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        batchOnHandshake: true,
        batchOnHandshakeDuration: 400,
        batchInterval: 50
      });
      bindFailureHandlers(server);

      let receivedServerMessages = [];

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);

          (async () => {
            for await (let {message} of socket.listener('message')) {
              receivedServerMessages.push(message);
            }
          })();
        }
      })();

      let subscribeMiddlewareCounter = 0;

      // Each subscription should pass through the middleware individually, even
      // though they were sent as a batch/array.
      server.setMiddleware(server.MIDDLEWARE_INBOUND, async function (middlewareStream) {
        for await (let action of middlewareStream) {
          if (action.type === AGAction.SUBSCRIBE) {
            subscribeMiddlewareCounter++;
            assert.equal(action.channel.indexOf('my-channel-'), 0);
            if (action.channel === 'my-channel-10') {
              assert.equal(JSON.stringify(action.data), JSON.stringify({foo: 123}));
            } else if (action.channel === 'my-channel-12') {
              // Block my-channel-12
              let err = new Error('You cannot subscribe to channel 12');
              err.name = 'UnauthorizedSubscribeError';
              action.block(err);
              continue;
            }
          }
          action.allow();
        }
      });

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER,
        batchOnHandshake: true,
        batchOnHandshakeDuration: 100,
        batchInterval: 50
      });

      let receivedClientMessages = [];
      (async () => {
        for await (let {message} of client.listener('message')) {
          receivedClientMessages.push(message);
        }
      })();

      let channelList = [];
      for (let i = 0; i < 20; i++) {
        let subscriptionOptions = {};
        if (i === 10) {
          subscriptionOptions.data = {foo: 123};
        }
        channelList.push(
          client.subscribe('my-channel-' + i, subscriptionOptions)
        );
      }

      (async () => {
        for await (let event of channelList[12].listener('subscribe')) {
          throw new Error('The my-channel-12 channel should have been blocked by MIDDLEWARE_SUBSCRIBE');
        }
      })();

      (async () => {
        for await (let event of channelList[12].listener('subscribeFail')) {
          assert.notEqual(event.error, null);
          assert.equal(event.error.name, 'UnauthorizedSubscribeError');
        }
      })();

      (async () => {
        for await (let event of channelList[19].listener('subscribe')) {
          client.transmitPublish('my-channel-19', 'Hello!');
        }
      })();

      for await (let data of channelList[19]) {
        assert.equal(data, 'Hello!');
        assert.equal(subscribeMiddlewareCounter, 20);
        break;
      }

      assert.notEqual(receivedServerMessages[0], null);
      // All 20 subscriptions should arrive as a single message.
      assert.equal(JSON.parse(receivedServerMessages[0]).length, 20);

      assert.equal(Array.isArray(JSON.parse(receivedClientMessages[0])), false);
      assert.equal(JSON.parse(receivedClientMessages[1]).length, 20);
    });

    it('The batchOnHandshake option should not break the order of subscribe and publish', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE,
        batchOnHandshake: true,
        batchOnHandshakeDuration: 400,
        batchInterval: 50
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();

      client = socketClusterClient.create({
        hostname: clientOptions.hostname,
        port: PORT_NUMBER,
        autoConnect: false,
        batchOnHandshake: true,
        batchOnHandshakeDuration: 100,
        batchInterval: 50
      });

      let receivedMessage;

      let fooChannel = client.subscribe('foo');
      client.transmitPublish('foo', 'bar');

      for await (let data of fooChannel) {
        receivedMessage = data;
        break;
      }
    });
  });

  describe('Socket Ping/pong', function () {
    describe('When pingTimeoutDisabled is not set', function () {
      beforeEach('Launch server with ping options before start', async function () {
        // Intentionally make pingInterval higher than pingTimeout, that
        // way the client will never receive a ping or send back a pong.
        server = socketClusterServer.listen(PORT_NUMBER, {
          authKey: serverOptions.authKey,
          wsEngine: WS_ENGINE,
          pingInterval: 2000,
          pingTimeout: 500
        });
        bindFailureHandlers(server);

        await server.listener('ready').once();
      });

      it('Should disconnect socket if server does not receive a pong from client before timeout', async function () {
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });

        let serverWarning = null;
        (async () => {
          for await (let {warning} of server.listener('warning')) {
            serverWarning = warning;
          }
        })();

        let serverDisconnectionCode = null;
        (async () => {
          for await (let event of server.listener('disconnection')) {
            serverDisconnectionCode = event.code;
          }
        })();

        let clientError = null;
        (async () => {
          for await (let {error} of client.listener('error')) {
            clientError = error;
          }
        })();

        let clientDisconnectCode = null;
        (async () => {
          for await (let event of client.listener('disconnect')) {
            clientDisconnectCode = event.code;
          }
        })();

        await wait(1000);
        assert.notEqual(clientError, null);
        assert.equal(clientError.name, 'SocketProtocolError');
        assert.equal(clientDisconnectCode === 4000 || clientDisconnectCode === 4001, true);

        assert.notEqual(serverWarning, null);
        assert.equal(serverWarning.name, 'SocketProtocolError');
        assert.equal(clientDisconnectCode === 4000 || clientDisconnectCode === 4001, true);
      });
    });

    describe('When pingTimeoutDisabled is true', function () {
      beforeEach('Launch server with ping options before start', async function () {
        // Intentionally make pingInterval higher than pingTimeout, that
        // way the client will never receive a ping or send back a pong.
        server = socketClusterServer.listen(PORT_NUMBER, {
          authKey: serverOptions.authKey,
          wsEngine: WS_ENGINE,
          pingInterval: 2000,
          pingTimeout: 500,
          pingTimeoutDisabled: true
        });
        bindFailureHandlers(server);

        await server.listener('ready').once();
      });

      it('Should not disconnect socket if server does not receive a pong from client before timeout', async function () {
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER,
          pingTimeoutDisabled: true
        });

        let serverWarning = null;
        (async () => {
          for await (let {warning} of server.listener('warning')) {
            serverWarning = warning;
          }
        })();

        let serverDisconnectionCode = null;
        (async () => {
          for await (let event of server.listener('disconnection')) {
            serverDisconnectionCode = event.code;
          }
        })();

        let clientError = null;
        (async () => {
          for await (let {error} of client.listener('error')) {
            clientError = error;
          }
        })();

        let clientDisconnectCode = null;
        (async () => {
          for await (let event of client.listener('disconnect')) {
            clientDisconnectCode = event.code;
          }
        })();

        await wait(1000);
        assert.equal(clientError, null);
        assert.equal(clientDisconnectCode, null);

        assert.equal(serverWarning, null);
        assert.equal(serverDisconnectionCode, null);
      });
    });

    describe('When pingTimeout is greater than pingInterval', function () {
      beforeEach('Launch server with ping options before start', async function () {
        // Intentionally make pingInterval higher than pingTimeout, that
        // way the client will never receive a ping or send back a pong.
        server = socketClusterServer.listen(PORT_NUMBER, {
          authKey: serverOptions.authKey,
          wsEngine: WS_ENGINE,
          pingInterval: 400,
          pingTimeout: 1000
        });
        bindFailureHandlers(server);

        await server.listener('ready').once();
      });

      it('Should not disconnect socket if server receives a pong from client before timeout', async function () {
        client = socketClusterClient.create({
          hostname: clientOptions.hostname,
          port: PORT_NUMBER
        });

        let serverWarning = null;
        (async () => {
          for await (let {warning} of server.listener('warning')) {
            serverWarning = warning;
          }
        })();

        let serverDisconnectionCode = null;
        (async () => {
          for await (let event of server.listener('disconnection')) {
            serverDisconnectionCode = event.code;
          }
        })();

        let clientError = null;
        (async () => {
          for await (let {error} of client.listener('error')) {
            clientError = error;
          }
        })();

        let clientDisconnectCode = null;
        (async () => {
          for await (let event of client.listener('disconnect')) {
            clientDisconnectCode = event.code;
          }
        })();

        await wait(2000);
        assert.equal(clientError, null);
        assert.equal(clientDisconnectCode, null);

        assert.equal(serverWarning, null);
        assert.equal(serverDisconnectionCode, null);
      });
    });
  });

  describe('Middleware', function () {
    beforeEach('Launch server without middleware before start', async function () {
      server = socketClusterServer.listen(PORT_NUMBER, {
        authKey: serverOptions.authKey,
        wsEngine: WS_ENGINE
      });
      bindFailureHandlers(server);

      (async () => {
        for await (let {socket} of server.listener('connection')) {
          connectionHandler(socket);
        }
      })();

      await server.listener('ready').once();
    });

    describe('MIDDLEWARE_HANDSHAKE', function () {
      describe('HANDSHAKE_WS action', function () {
        it('Delaying handshake for one client should not affect other clients', async function () {
          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.HANDSHAKE_WS) {
                if (action.request.url.indexOf('?delayMe=true') !== -1) {
                  // Long delay.
                  await wait(5000);
                  action.allow();
                  continue;
                }
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          let clientA = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let clientB = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER,
            query: {
              delayMe: true
            }
          });

          let clientAIsConnected = false;
          let clientBIsConnected = false;

          (async () => {
            await clientA.listener('connect').once();
            clientAIsConnected = true;
          })();

          (async () => {
            await clientB.listener('connect').once();
            clientBIsConnected = true;
          })();

          await wait(100);

          assert.equal(clientAIsConnected, true);
          assert.equal(clientBIsConnected, false);

          clientA.disconnect();
          clientB.disconnect();
        });
      });

      describe('HANDSHAKE_SC action', function () {
        it('Should trigger correct events if MIDDLEWARE_HANDSHAKE blocks with an error', async function () {
          let middlewareWasExecuted = false;
          let serverWarnings = [];
          let clientErrors = [];
          let abortStatus;

          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow, block} of middlewareStream) {
              if (type === AGAction.HANDSHAKE_SC) {
                await wait(100);
                middlewareWasExecuted = true;
                let err = new Error('AG handshake failed because the server was too lazy');
                err.name = 'TooLazyHandshakeError';
                block(err);
                continue;
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          (async () => {
            for await (let {warning} of server.listener('warning')) {
              serverWarnings.push(warning);
            }
          })();

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          (async () => {
            for await (let {error} of client.listener('error')) {
              clientErrors.push(error);
            }
          })();

          (async () => {
            let event = await client.listener('connectAbort').once();
            abortStatus = event.code;
          })();

          await wait(200);
          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(clientErrors[0], null);
          assert.equal(clientErrors[0].name, 'TooLazyHandshakeError');
          assert.notEqual(clientErrors[1], null);
          assert.equal(clientErrors[1].name, 'SocketProtocolError');
          assert.notEqual(serverWarnings[0], null);
          assert.equal(serverWarnings[0].name, 'TooLazyHandshakeError');
          assert.notEqual(abortStatus, null);
        });

        it('Should send back default 4008 status code if MIDDLEWARE_HANDSHAKE blocks without providing a status code', async function () {
          let middlewareWasExecuted = false;
          let abortStatus;
          let abortReason;

          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow, block} of middlewareStream) {
              if (type === AGAction.HANDSHAKE_SC) {
                await wait(100);
                middlewareWasExecuted = true;
                let err = new Error('AG handshake failed because the server was too lazy');
                err.name = 'TooLazyHandshakeError';
                block(err);
                continue;
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          (async () => {
            let event = await client.listener('connectAbort').once();
            abortStatus = event.code;
            abortReason = event.reason;
          })();

          await wait(200);
          assert.equal(middlewareWasExecuted, true);
          assert.equal(abortStatus, 4008);
          assert.equal(abortReason, 'TooLazyHandshakeError: AG handshake failed because the server was too lazy');
        });

        it('Should send back custom status code if MIDDLEWARE_HANDSHAKE blocks by providing a status code', async function () {
          let middlewareWasExecuted = false;
          let abortStatus;
          let abortReason;

          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow, block} of middlewareStream) {
              if (type === AGAction.HANDSHAKE_SC) {
                await wait(100);
                middlewareWasExecuted = true;
                let err = new Error('AG handshake failed because of invalid query auth parameters');
                err.name = 'InvalidAuthQueryHandshakeError';
                // Set custom 4501 status code as a property of the error.
                // We will treat this code as a fatal authentication failure on the front end.
                // A status code of 4500 or higher means that the client shouldn't try to reconnect.
                err.statusCode = 4501;
                block(err);
                continue;
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          (async () => {
            let event = await client.listener('connectAbort').once();
            abortStatus = event.code;
            abortReason = event.reason;
          })();

          await wait(200);
          assert.equal(middlewareWasExecuted, true);
          assert.equal(abortStatus, 4501);
          assert.equal(abortReason, 'InvalidAuthQueryHandshakeError: AG handshake failed because of invalid query auth parameters');
        });

        it('Should connect with a delay if allow() is called after a timeout inside the middleware function', async function () {
          let createConnectionTime = null;
          let connectEventTime = null;
          let abortStatus;
          let abortReason;

          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow} of middlewareStream) {
              if (type === AGAction.HANDSHAKE_SC) {
                await wait(500);
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          createConnectionTime = Date.now();
          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          (async () => {
            let event = await client.listener('connectAbort').once();
            abortStatus = event.code;
            abortReason = event.reason;
          })();

          await client.listener('connect').once();
          connectEventTime = Date.now();
          assert.equal(connectEventTime - createConnectionTime > 400, true);
        });

        it('Should not be allowed to call req.socket.setAuthToken from inside middleware', async function () {
          let didAuthenticationEventTrigger = false;
          let setAuthTokenError;

          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, async function (middlewareStream) {
            for await (let {socket, type, allow, block} of middlewareStream) {
              if (type === AGAction.HANDSHAKE_SC) {
                try {
                  await socket.setAuthToken({username: 'alice'});
                } catch (error) {
                  setAuthTokenError = error;
                }
              }
              allow();
            }
          });

          (async () => {
            let event = await server.listener('authentication').once();
            didAuthenticationEventTrigger = true;
          })();

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let event = await client.listener('connect').once();
          assert.equal(event.isAuthenticated, false);
          assert.equal(client.authState, client.UNAUTHENTICATED);
          assert.equal(client.authToken, null);
          assert.equal(didAuthenticationEventTrigger, false);
          assert.notEqual(setAuthTokenError, null);
          assert.equal(setAuthTokenError.name, 'InvalidActionError');
        });

        it('Delaying handshake for one client should not affect other clients', async function () {
          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.HANDSHAKE_SC) {
                if (action.socket.request.url.indexOf('?delayMe=true') !== -1) {
                  // Long delay.
                  await wait(5000);
                  action.allow();
                  continue;
                }
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_HANDSHAKE, middlewareFunction);

          let clientA = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let clientB = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER,
            query: {
              delayMe: true
            }
          });

          let clientAIsConnected = false;
          let clientBIsConnected = false;

          (async () => {
            await clientA.listener('connect').once();
            clientAIsConnected = true;
          })();

          (async () => {
            await clientB.listener('connect').once();
            clientBIsConnected = true;
          })();

          await wait(100);

          assert.equal(clientAIsConnected, true);
          assert.equal(clientBIsConnected, false);

          clientA.disconnect();
          clientB.disconnect();
        });
      });
    });

    describe('MIDDLEWARE_INBOUND', function () {
      describe('INVOKE action', function () {
        it('Should run INVOKE action in middleware if client invokes an RPC', async function () {
          let middlewareWasExecuted = false;
          let middlewareAction = null;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.INVOKE) {
                middlewareWasExecuted = true;
                middlewareAction = action;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let result = await client.invoke('proc', 123);

          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(middlewareAction, null);
          assert.equal(result, 'success 123');
        });

        it('Should send back custom Error if INVOKE action in middleware blocks the client RPC', async function () {
          let middlewareWasExecuted = false;
          let middlewareAction = null;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.INVOKE) {
                middlewareWasExecuted = true;
                middlewareAction = action;

                let customError = new Error('Invoke action was blocked');
                customError.name = 'BlockedInvokeError';
                action.block(customError);
                continue;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let result;
          let error;
          try {
            result = await client.invoke('proc', 123);
          } catch (err) {
            error = err;
          }

          assert.equal(result, null);
          assert.notEqual(error, null);
          assert.equal(error.name, 'BlockedInvokeError');
        });
      });

      describe('AUTHENTICATE action', function () {
        it('Should not run AUTHENTICATE action in middleware if JWT token does not exist', async function () {
          let middlewareWasExecuted = false;
          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow} of middlewareStream) {
              if (type === AGAction.AUTHENTICATE) {
                middlewareWasExecuted = true;
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          await client.listener('connect').once();
          assert.notEqual(middlewareWasExecuted, true);
        });

        it('Should run AUTHENTICATE action in middleware if JWT token exists', async function () {
          global.localStorage.setItem('socketcluster.authToken', validSignedAuthTokenBob);
          let middlewareWasExecuted = false;

          let middlewareFunction = async function (middlewareStream) {
            for await (let {type, allow} of middlewareStream) {
              if (type === AGAction.AUTHENTICATE) {
                middlewareWasExecuted = true;
              }
              allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          (async () => {
            try {
              await client.invoke('login', {username: 'bob'});
            } catch (err) {}
          })();

          await client.listener('authenticate').once();
          assert.equal(middlewareWasExecuted, true);
        });
      });

      describe('PUBLISH_IN action', function () {
        it('Should run PUBLISH_IN action in middleware if client publishes to a channel', async function () {
          let middlewareWasExecuted = false;
          let middlewareAction = null;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_IN) {
                middlewareWasExecuted = true;
                middlewareAction = action;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          await client.invokePublish('hello', 'world');

          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(middlewareAction, null);
          assert.equal(middlewareAction.channel, 'hello');
          assert.equal(middlewareAction.data, 'world');
        });

        it('Should be able to delay and block publish using PUBLISH_IN middleware', async function () {
          let middlewareWasExecuted = false;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_IN) {
                middlewareWasExecuted = true;
                let error = new Error('Blocked by middleware');
                error.name = 'BlockedError';
                await wait(50);
                action.block(error);
                continue;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let helloChannel = client.subscribe('hello');
          await helloChannel.listener('subscribe').once();

          let receivedMessages = [];
          (async () => {
            for await (let data of helloChannel) {
              receivedMessages.push(data);
            }
          })();

          let error;
          try {
            await client.invokePublish('hello', 'world');
          } catch (err) {
            error = err;
          }
          await wait(100);

          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(error, null);
          assert.equal(error.name, 'BlockedError');
          assert.equal(receivedMessages.length, 0);
        });

        it('Delaying PUBLISH_IN action for one client should not affect other clients', async function () {
          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_IN) {
                if (action.socket.request.url.indexOf('?delayMe=true') !== -1) {
                  // Long delay.
                  await wait(5000);
                  action.allow();
                  continue;
                }
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          let clientA = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let clientB = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER,
            query: {
              delayMe: true
            }
          });

          let clientC = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          await clientC.listener('connect').once();

          let receivedMessages = [];
          (async () => {
            for await (let data of clientC.subscribe('foo')) {
              receivedMessages.push(data);
            }
          })();

          clientA.transmitPublish('foo', 'a1');
          clientA.transmitPublish('foo', 'a2');

          clientB.transmitPublish('foo', 'b1');
          clientB.transmitPublish('foo', 'b2');

          await wait(100);

          assert.equal(receivedMessages.length, 2);
          assert.equal(receivedMessages[0], 'a1');
          assert.equal(receivedMessages[1], 'a2');

          clientA.disconnect();
          clientB.disconnect();
          clientC.disconnect();
        });

        it('Should allow to change message in middleware when client invokePublish', async function() {
          let clientMessage = 'world';
          let middlewareMessage = 'intercepted';
          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_IN) {
                action.allow({data: middlewareMessage});
              } else {
                action.allow();
              }
            }
          };

          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let helloChannel = client.subscribe('hello');
          await helloChannel.listener('subscribe').once();

          let receivedMessages = [];
          (async () => {
            for await (let data of helloChannel) {
              receivedMessages.push(data);
            }
          })();

          let error;
          try {
            await client.invokePublish('hello', clientMessage);
          } catch (err) {
            error = err;
          }

          await wait(100);

          assert.notEqual(clientMessage, middlewareMessage);
          assert.equal(receivedMessages[0], middlewareMessage);
        });

        it('Should allow to change message in middleware when client transmitPublish', async function() {
          let clientMessage = 'world';
          let middlewareMessage = 'intercepted';
          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_IN) {
                action.allow({data: middlewareMessage});
              } else {
                action.allow();
              }
            }
          };

          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          let helloChannel = client.subscribe('hello');
          await helloChannel.listener('subscribe').once();

          let receivedMessages = [];
          (async () => {
            for await (let data of helloChannel) {
              receivedMessages.push(data);
            }
          })();

          let error;
          try {
            await client.transmitPublish('hello', clientMessage);
          } catch (err) {
            error = err;
          }

          await wait(100);

          assert.notEqual(clientMessage, middlewareMessage);
          assert.equal(receivedMessages[0], middlewareMessage);
        })
      });

      describe('SUBSCRIBE action', function () {
        it('Should run SUBSCRIBE action in middleware if client subscribes to a channel', async function () {
          let middlewareWasExecuted = false;
          let middlewareAction = null;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.SUBSCRIBE) {
                middlewareWasExecuted = true;
                middlewareAction = action;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          await client.subscribe('hello').listener('subscribe').once();

          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(middlewareAction, null);
          assert.equal(middlewareAction.channel, 'hello');
        });

        it('Should maintain pub/sub order if SUBSCRIBE action is delayed in middleware even if client starts out in disconnected state', async function () {
          let middlewareActions = [];

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              middlewareActions.push(action);
              if (action.type === AGAction.SUBSCRIBE) {
                await wait(100);
                action.allow();
                continue;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_INBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER,
            autoConnect: false
          });

          let receivedMessage;

          let fooChannel = client.subscribe('foo');
          client.transmitPublish('foo', 'bar');

          for await (let data of fooChannel) {
            receivedMessage = data;
            break;
          }

          assert.equal(receivedMessage, 'bar');
          assert.equal(middlewareActions.length, 2);
          assert.equal(middlewareActions[0].type, AGAction.SUBSCRIBE);
          assert.equal(middlewareActions[0].channel, 'foo');
          assert.equal(middlewareActions[1].type, AGAction.PUBLISH_IN);
          assert.equal(middlewareActions[1].channel, 'foo');
        });
      });
    });

    describe('MIDDLEWARE_OUTBOUND', function () {
      describe('PUBLISH_OUT action', function () {
        it('Should run PUBLISH_OUT action in middleware if client publishes to a channel', async function () {
          let middlewareWasExecuted = false;
          let middlewareAction = null;

          let middlewareFunction = async function (middlewareStream) {
            for await (let action of middlewareStream) {
              if (action.type === AGAction.PUBLISH_OUT) {
                middlewareWasExecuted = true;
                middlewareAction = action;
              }
              action.allow();
            }
          };
          server.setMiddleware(server.MIDDLEWARE_OUTBOUND, middlewareFunction);

          client = socketClusterClient.create({
            hostname: clientOptions.hostname,
            port: PORT_NUMBER
          });

          await client.subscribe('hello').listener('subscribe').once();
          await client.invokePublish('hello', 123);

          assert.equal(middlewareWasExecuted, true);
          assert.notEqual(middlewareAction, null);
          assert.equal(middlewareAction.channel, 'hello');
          assert.equal(middlewareAction.data, 123);
        });
      });
    });
  });
});
