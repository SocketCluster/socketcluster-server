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

module.exports = Action;
