const scErrors = require('sc-errors');
const InvalidActionError = scErrors.InvalidActionError;

function Response(socket, id) {
  this.socket = socket;
  this.id = id;
  this.sent = false;
}

Response.prototype._respond = function (responseData, options) {
  if (this.sent) {
    throw new InvalidActionError(`Response ${this.id} has already been sent`);
  } else {
    this.sent = true;
    this.socket.sendObject(responseData, options);
  }
};

Response.prototype.end = function (data, options) {
  if (this.id) {
    let responseData = {
      rid: this.id
    };
    if (data !== undefined) {
      responseData.data = data;
    }
    this._respond(responseData, options);
  }
};

Response.prototype.error = function (error, data, options) {
  if (this.id) {
    let err = scErrors.dehydrateError(error);

    let responseData = {
      rid: this.id,
      error: err
    };
    if (data !== undefined) {
      responseData.data = data;
    }

    this._respond(responseData, options);
  }
};

Response.prototype.callback = function (error, data, options) {
  if (error) {
    this.error(error, data, options);
  } else {
    this.end(data, options);
  }
};

module.exports.Response = Response;
