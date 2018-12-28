# asyngular-server
Minimal server module for Asyngular

This is a stand-alone server module for Asyngular (SocketCluster with full async/await support).
Asyngular's protocol is backwards compatible with the SocketCluster protocol.

## Setting up

You will need to install both ```asyngular-server``` and ```asyngular-client``` (https://github.com/SocketCluster/asyngular-client).

To install this module:
```npm install asyngular-server```

## Usage

You need to attach it to an existing Node.js http or https server (example):
```js
var http = require('http');
var asyngularServer = require('asyngular-server');

var httpServer = http.createServer();
var agServer = asyngularServer.attach(httpServer);

(async () => {
  // Handle new inbound sockets.
  for await (let {socket} of agServer.listener('connection')) {

    (async () => {
      // Set up a loop to handle and respond to RPCs for a procedure.
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

    (async () => {
      // Set up a loop to handle remote transmitted events.
      for await (let data of socket.receiver('customRemoteEvent')) {
        // ...
      }
    })();

  }
})();

httpServer.listen(8000);
```

For more detailed examples of how to use Asyngular, see `test/integration.js`.
Also, see tests from the `asyngular-client` module.

Asyngular can work without the `for-await-of` loop; a `while` loop with `await` statements can be used instead.
See https://github.com/SocketCluster/stream-demux#usage

## Running the tests

- Clone this repo: `git clone git@github.com:SocketCluster/asyngular-server.git`
- Navigate to project directory: `cd asyngular-server`
- Install all dependencies: `npm install`
- Run the tests: `npm test`

## Benefits of async `Iterable` over `EventEmitter`

- **More readable**: Code is written sequentially from top to bottom. Avoids event handler callback hell. It's also much easier to write and read complex integration test scenarios.
- **More manageable**: No need to remember to unbind listeners with `removeEventListener(...)`; just `break` out of the `for-await-of` loop to stop consuming. This also encourages a more declarative style of coding.
- **Safer**: Each kind of async operation can be declared to run sequentially without missing any events. On the other hand, with `EventEmitter`, the listener function for the same event cannot be prevented from running multiple times in parallel; this can cause unintended side effects.
