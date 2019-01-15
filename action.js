const scErrors = require('sc-errors');
const InvalidActionError = scErrors.InvalidActionError;

function Action() {
  this.outcome = null;
  this.promise = new Promise((resolve, reject) => {
    this._resolve = resolve;
    this._reject = reject;
  });

  this.allow = (packet) => {
    if (this.outcome) {
      throw new InvalidActionError(`Action ${this.type} has already been ${this.outcome}; cannot allow`);
    }
    this.outcome = 'allowed';
    this._resolve(packet);
  };

  this.block = (error) => {
    if (this.outcome) {
      throw new InvalidActionError(`Action ${this.type} has already been ${this.outcome}; cannot block`);
    }
    this.outcome = 'blocked';
    this._reject(error);
  };
}

Action.prototype.HANDSHAKE_WS = Action.HANDSHAKE_WS = 'handshakeWS';
Action.prototype.HANDSHAKE_AG = Action.HANDSHAKE_AG = 'handshakeAG';

Action.prototype.MESSAGE = Action.MESSAGE = 'message';

Action.prototype.TRANSMIT = Action.TRANSMIT = 'transmit';
Action.prototype.INVOKE = Action.INVOKE = 'invoke';
Action.prototype.SUBSCRIBE = Action.SUBSCRIBE = 'subscribe';
Action.prototype.PUBLISH_IN = Action.PUBLISH_IN = 'publishIn';
Action.prototype.PUBLISH_OUT = Action.PUBLISH_OUT = 'publishOut';
Action.prototype.AUTHENTICATE = Action.AUTHENTICATE = 'authenticate';

module.exports = Action;
