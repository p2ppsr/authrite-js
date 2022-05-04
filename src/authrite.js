const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
// The correct versions of EventSource and fetch should be used
// let fetch
// if (typeof window !== 'undefined') {
//   fetch = typeof window.fetch !== 'undefined'
//     ? window.fetch
//     : require('node-fetch')
// } else {
//   fetch = require('node-fetch')
// }
const fetch = require('node-fetch')

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
    * @param {String} serverUrl initiating  the request
    * @param {String} clientPrivateKey used for derivations
    * @param {String} initialRequestPath
    * @param {String} initialRequestMethod
    */
  constructor ({ serverUrl, clientPrivateKey, initialRequestPath = '/authrite/initialRequest', initialRequestMethod = 'POST' }) {
    this.initialRequestPath = initialRequestPath
    this.initalRequestMethod = initialRequestMethod
    this.client = new Client(clientPrivateKey)
    this.server = new Server(serverUrl, null, null, [], [])
  }

  /**
   * Derives the signing public key
   */
  derivePublicKey (serverIdentitiyKey, serverNonce) {
    return getPaymentAddress({
      senderPrivateKey: this.client.privateKey,
      recipientPublicKey: serverIdentitiyKey,
      invoiceNumber: 'authrite message signature-' + this.client.nonce + ' ' + serverNonce,
      returnType: 'publicKey'
    })
  }

  /**
   * Derives a corresponding private key
   */
  // derivePrivateKey (serverIdentitiyKey, serverNonce) {

  // }

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
    // console.log('Server Response: ', serverResponse)
    if (serverResponse.authrite === AUTHRITE_VERSION && serverResponse.messageType === 'initialResponse') {
      // Validate server signature
      // 1. Obtain the public key
      const signingPublicKey = this.derivePublicKey(serverResponse.identityKey, serverResponse.nonce)
      // 2. Construct the message for verification
      const messageToVerify = this.client.nonce + serverResponse.nonce
      // 3. Verify the signature
      const signature = bsv.crypto.Signature.fromString(serverResponse.signature)
      // console.log('Signature: ' + signature)
      // console.log('Message to verify: ' + messageToVerify)
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
    console.time()
    // Check for server parameters
    if (!this.server.identityPublicKey || !this.server.nonce) {
      await this.getServerParameters()
    }
    // Subsequent requests
    // Sign the request body,
    // When a client makes a new request, it generates a new requestNonce and uses it together with the server’s initialNonce for key derivation.
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const derivedClientPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: this.client.privateKey,
      senderPublicKey: this.server.identityPublicKey,
      invoiceNumber: 'authrite message signature-' + requestNonce + ' ' + this.server.nonce,
      returnType: 'hex'
    })
    const dataToSign = fetchConfig.payload ? fetchConfig.payload.toString() : this.server.baseUrl + routePath
    const requestSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
      bsv.PrivateKey.fromHex(derivedClientPrivateKey)
    )
    // Include X-Authrite-Signature and X-Authrite-Nonce headers
    // Send the signed Authrite request with the HTTP headers according to the specification.
    console.timeEnd()
    const response = await fetch(
      this.server.baseUrl + routePath,
      {
        ...fetchConfig,
        headers: {
          ...fetchConfig.headers,
          'X-Authrite': AUTHRITE_VERSION,
          'X-Authrite-Identity-Key': this.client.publicKey,
          'X-Authrite-Nonce': requestNonce,
          'X-Authrite-YourNonce': this.server.nonce,
          'X-Authrite-Certificates': this.client.certificates,
          'X-Authrite-Signature': requestSignature
        }
      }
    )
    // TODO: Add error handling
    // When the server response comes back, validate the signature according to the specification.
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: this.client.privateKey,
      recipientPublicKey: this.server.identityPublicKey,
      invoiceNumber: 'authrite message signature-' + requestNonce + ' ' + response.headers['X-Authrite-Nonce'],
      returnType: 'publicKey'
    })
    // 2. Construct the message for verification
    const messageToVerify = response.body
    // 3. Verify the signature
    const signature = bsv.crypto.Signature.fromString(response.headers['X-Authrite-Signature'])
    console.log('Signature: ' + signature)
    console.log('Message to verify: ' + messageToVerify)
    const verified = bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
      signature,
      bsv.PublicKey.fromString(signingPublicKey)
    )
    if (verified) {
      return response
    }
  }
}
module.exports = { Authrite }
