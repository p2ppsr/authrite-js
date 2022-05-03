// const boomerang = require('boomerang-http')
class Authrite {
  /**
    * Authrite Constructor
    * @param {String} server initiating  the request
    * @param {String} clientPrivateKey used for derivations
    * @param {String} initialRequestPath
    * @param {String} initialRequestMethod
    */
  constructor ({ server, clientPrivateKey, initialRequestPath = '/authrite/initialRequest', initialRequestMethod = 'POST' }) {
    this.server = server
    this.clientPrivateKey = clientPrivateKey
    this.initialRequestPath = initialRequestPath
    this.initalRequestMethod = initialRequestMethod
  }

  /**
   * Creates a new signed authrite request
   * @param {String} method The request type to use
   * @param {String} path used for the request
   * @param {String} data requested from the server
   */
  request (method = this.initalRequestMethod, path = this.initialRequestPath, data) {
    // TODO: Check for server parameters
    // TODO: Create a request signature using client key, server key, client-generated nonce, and server nonce.
    // TODO: Send the signed Authrite request with the HTTP headers according to the specification.
    // TODO: When the server response comes back, validate the signature according to the specification.
  }
}
module.exports = { Authrite }
