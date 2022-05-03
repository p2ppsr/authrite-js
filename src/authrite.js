const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress } = require('sendover')

// Client member data
const AUTHRITE_VERSION = '0.1'

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
    this.serverIdentityPublicKey = null
    this.serverNonce = null
    this.serverCertificates = [] // TODO: add support
    this.serverRequestedCertificates = [] // TODO: add support
    this.clientNonce = crypto.randomBytes(32).toString('base64')
    this.clientPrivateKey = clientPrivateKey
    this.clientPublicKey = bsv.PrivateKey.fromHex(clientPrivateKey).publicKey.toString()
    this.initialRequestPath = initialRequestPath
    this.initalRequestMethod = initialRequestMethod
  }

  // Get initial server parameters
  async getServerParameters () {
    // Fetch server parameters
    const serverResponse = await boomerang(
      this.initalRequestMethod,
      this.server + this.initialRequestPath,
      {
        authrite: AUTHRITE_VERSION,
        messageType: 'initialRequest',
        identityKey: this.clientPublicKey,
        nonce: this.clientNonce,
        requestedCertificates: [] // TODO: provide requested certificates
      }
    )

    // Populate server parameters
    if (serverResponse.authrite === AUTHRITE_VERSION && serverResponse.messageType === 'initialRequest') {
      // Validate server signature
      // 1. Obtain the public key
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.clientPrivateKey,
        recipientPublicKey: this.serverPublicKey,
        invoiceNumber: 'authrite message signature-' + this.clientNonce + ' ' + this.serverNonce,
        returnType: 'publicKey'
      })
      // 2. Construct the message for verification
      const messageToVerify = this.clientNonce + this.serverNonce
      // 3. Verify the signature
      const verified = bsv.crypto.ECDSA.verify(bsv.crypto.Hash.sha256(messageToVerify), serverResponse.signature, bsv.PublicKey.fromString(signingPublicKey))

      if (verified) {
        this.serverIdentityPublicKey = serverResponse.identityKey
        this.serverNonce = serverResponse.nonce
        this.serverRequestedCertificates = serverResponse.requestedCertificates // TODO: check certs
      } else {
        // Handle Error case
      }
    } else {
      // DO something
    }
  }

  /**
  reates a new signed authrite request
   * @param {String} method The request type to use
   * @param {String} path used for the request
   * @param {String} data requested from the server
   */
  async request (method = this.initalRequestMethod, path = this.initialRequestPath, data) {
    // Check for server parameters
    if (!this.serverIdentityPublicKey || !this.serverNonce) {
      await this.getServerParameters()
    }
    // TODO: Create a request signature using client key, server key, client-generated nonce, and server nonce.
    // TODO: Send the signed Authrite request with the HTTP headers according to the specification.
    // TODO: When the server response comes back, validate the signature according to the specification.
  }
}
module.exports = { Authrite }
