# asyngular-server
Minimal server module for Asyngular

This is a stand-alone server module for Asyngular. This module offers the most flexibility when creating a Asyngular service but requires the most work to setup.
The repository for the full-featured framework is here: https://github.com/SocketCluster/asyngular

## Setting up

You will need to install ```asyngular-server``` and ```asyngular-client``` (https://github.com/SocketCluster/asyngular-client) separately.

To install this module:
```npm install asyngular-server```

Note that the full Asyngular framework (https://github.com/SocketCluster/asyngular) uses this module behind the scenes so the API is exactly the same and it works with the asyngular-client out of the box.
The main difference with using asyngular-server is that you won't get features like:

- Automatic scalability across multiple CPU cores.
- Resilience; you are responsible for respawning the process if it crashes.
- Convenience; It requires more work up front to get working (not good for beginners).
- Pub/sub channels won't scale across multiple asyngular-server processes/hosts by default.\*

\* Note that the ```asyngularServer.attach(httpServer, options);``` takes an optional options argument which can have a ```brokerEngine``` property - By default, asyngular-server
uses ```sc-simple-broker``` which is a basic single-process in-memory broker. If you want to add your own brokerEngine (for example to scale your asyngular-servers across multiple cores/hosts), then you might want to look at how sc-simple-broker was implemented.

The full Asyngular framework uses a different broker engine: ```sc-broker-cluster```(https://github.com/SocketCluster/sc-broker-cluster) - This is a more complex brokerEngine - It allows messages to be brokered between
multiple processes and can be synchronized with remote hosts too so you can get both horizontal and vertical scalability.

The main benefit of this module is that it gives you maximum flexibility. You just need to attach it to a Node.js http server so you can use it alongside pretty much any framework.
