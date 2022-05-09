const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
// The correct versions of EventSource and fetch should be used
let fetch
if (typeof window !== 'undefined') {
  fetch = typeof window.fetch !== 'undefined'
    ? window.fetch
    : require('node-fetch')
} else {
  fetch = require('node-fetch')
}

const AUTHRITE_VERSION = '0.1'

/**
 * Defines an Authrite Client
 * @params {String} privateKey of client
 */
class Client {
  constructor (privateKey) {
    this.privateKey = privateKey
    this.publicKey = bsv.PrivateKey.fromHex(privateKey).publicKey.toString()
    this.nonce = crypto.randomBytes(32).toString('base64')
    this.certificates = []
  }
}
/**
 * Defines an Authrite Server
 * @params {String} baseUrl of the server
 * @params {String} identityPublicKey of server
 * @params {String} nonce
 * @params {String} certificates provided by the server
 * @params {String} requestedCertificates from the server
 */
class Server {
  constructor (baseUrl, identityPublicKey, nonce, certificates, requestedCertificates) {
    this.baseUrl = baseUrl
    this.identityPublicKey = identityPublicKey
    this.nonce = nonce
    this.certificates = certificates
    this.requestedCertificates = requestedCertificates
  }
}

class Authrite {
  /**
    * Authrite Constructor
    * @param {String} baseUrl initiating  the request
    * @param {String} clientPrivateKey used for derivations
    * @param {String} initialRequestPath
    * @param {String} initialRequestMethod
    */
  constructor ({ baseUrl, clientPrivateKey, initialRequestPath = '/authrite/initialRequest', initialRequestMethod = 'POST' }) {
    this.initialRequestPath = initialRequestPath
    this.initalRequestMethod = initialRequestMethod
    if (!clientPrivateKey) throw new Error('Please provide a valid client private key!')
    this.client = new Client(clientPrivateKey)
    if (!baseUrl) throw new Error('Please provide a valid base server URL!')
    this.server = new Server(baseUrl, null, null, [], [])
  }

  // Fetch initial server parameters
  async getServerParameters () {
    const serverResponse = await boomerang(
      this.initalRequestMethod,
      this.server.baseUrl + this.initialRequestPath,
      {
        authrite: AUTHRITE_VERSION,
        messageType: 'initialRequest',
        identityKey: this.client.publicKey,
        nonce: this.client.nonce,
        requestedCertificates: this.server.requestedCertificates // TODO: provide requested certificates
      }
    )
    if (serverResponse.authrite === AUTHRITE_VERSION && serverResponse.messageType === 'initialResponse') {
      // Validate server signature
      // 1. Obtain the public key
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.client.privateKey,
        recipientPublicKey: serverResponse.identityKey,
        invoiceNumber: 'authrite message signature-' + this.client.nonce + ' ' + serverResponse.nonce,
        returnType: 'publicKey'
      })
      // 2. Construct the message for verification
      const messageToVerify = this.client.nonce + serverResponse.nonce
      // 3. Verify the signature
      const signature = bsv.crypto.Signature.fromString(serverResponse.signature)
      const verified = bsv.crypto.ECDSA.verify(
        bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
        signature,
        bsv.PublicKey.fromString(signingPublicKey)
      )
      // Determine if the signature was verified
      if (verified) {
        this.server.identityPublicKey = serverResponse.identityKey
        this.server.nonce = serverResponse.nonce
        this.server.requestedCertificates = serverResponse.requestedCertificates // TODO: check certs
      } else {
        throw new Error('Unable to verify server signature!')
      }
    } else {
      throw new Error('Authrite version incompatible')
    }
  }

  /**
  Creates a new signed authrite request
   * @param {String} method The request type to use
   * @param {String} path used for the request
   * @param {Object} payload requested from the server
   * @param {Object} headers to include in the request
   */
  async request (routePath, fetchConfig = {}) {
    // Check for server parameters
    if (!this.server.identityPublicKey || !this.server.nonce) {
      await this.getServerParameters()
    }
    // For subsequent requests,
    // we want to generates a new requestNonce
    // and use it together with the server’s initialNonce for key derivation
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const derivedClientPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: this.client.privateKey,
      senderPublicKey: this.server.identityPublicKey,
      invoiceNumber: 'authrite message signature-' + requestNonce + ' ' + this.server.nonce,
      returnType: 'hex'
    })
    // Check if a fetchConfig has data that was passed in
    const dataToSign = Object.keys(fetchConfig).length === 0 ? this.server.baseUrl + routePath : JSON.stringify(fetchConfig.payload)
    const requestSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
      bsv.PrivateKey.fromHex(derivedClientPrivateKey)
    )
    // Send the signed Authrite request with the HTTP headers according to the specification
    let fetchRequest = {
      headers: {
        ...fetchConfig.headers,
        'Content-Type': 'application/json',
        'X-Authrite': AUTHRITE_VERSION,
        'X-Authrite-Identity-Key': this.client.publicKey,
        'X-Authrite-Nonce': requestNonce,
        'X-Authrite-YourNonce': this.server.nonce,
        'X-Authrite-Certificates': this.client.certificates,
        'X-Authrite-Signature': requestSignature.toString()
      }
    }
    // Check if the user is trying to send a payload
    if (fetchConfig.payload) {
      fetchRequest = {
        body: JSON.stringify(fetchConfig.payload),
        method: fetchConfig.method ? fetchConfig.method : 'POST',
        ...fetchRequest
      }
    }
    // Send the fetch node request and get the response
    const response = await fetch(
      this.server.baseUrl + routePath,
      fetchRequest
    )
    if (!response) {
      throw new Error('Failed to get response from server!')
    }
    // When the server response comes back, validate the signature according to the specification
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: this.client.privateKey,
      recipientPublicKey: this.server.identityPublicKey,
      invoiceNumber: 'authrite message signature-' + requestNonce + ' ' + response.headers.get('X-Authrite-Nonce'),
      returnType: 'publicKey'
    })

    // 2. Construct the message for verification
    const messageToVerify = await response.arrayBuffer()
    // 3. Verify the signature
    const signature = bsv.crypto.Signature.fromString(
      response.headers.get('x-authrite-signature')
    )
    const verified = bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
      signature,
      bsv.PublicKey.fromString(signingPublicKey)
    )
    if (verified) {
      return {
        headers: response.headers,
        body: messageToVerify
      }
    } else {
      throw new Error('Unable to verify server response')
    }
  }
}
module.exports = { Authrite }
