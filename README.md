# Asyngular server
Minimal server module for Asyngular

This is a stand-alone server module for Asyngular (SocketCluster with full async/await support).
Asyngular's protocol is backwards compatible with the SocketCluster protocol.

## Setting up

You will need to install both ```asyngular-server``` and ```asyngular-client``` (https://github.com/SocketCluster/asyngular-client).

To install this module:
```bash
npm install asyngular-server
```

## Usage

You need to attach it to an existing Node.js http or https server (example):
```js
const http = require('http');
const asyngularServer = require('asyngular-server');

let httpServer = http.createServer();
let agServer = asyngularServer.attach(httpServer);

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
- **More manageable**: No need to remember to unbind listeners with `removeListener(...)`; just `break` out of the `for-await-of` loop to stop consuming. This also encourages a more declarative style of coding.
- **Safer**: Each event can be processed sequentially without missing any events. On the other hand, with `EventEmitter`, the listener function for the same event cannot be prevented from running multiple times in parallel; this can cause unintended side effects.

## License

(The MIT License)

Copyright (c) 2013-2019 SocketCluster.io

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
