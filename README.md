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
var asyngularServer = require('socketcluster-server');

var httpServer = http.createServer();
var agServer = asyngularServer.attach(httpServer);

(async () => {
  // Handle new inbound sockets.
  for await (let {socket} of server.listener('connection')) {

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

## Running the integration tests

- Clone this repo: `git clone git@github.com:SocketCluster/asyngular-server.git`
- Navigate to project directory: `cd asyngular-server`
- Install all dependencies: `npm install`
- Run the tests `npm test`

\* Note that the ```asyngularServer.attach(httpServer, options);``` takes an optional options argument which can have a ```brokerEngine``` property - By default, asyngular-server
uses ```sc-simple-broker``` which is a basic single-process in-memory broker. If you want to add your own brokerEngine (for example to scale your asyngular-servers across multiple cores/hosts), then you might want to look at how sc-simple-broker was implemented.
