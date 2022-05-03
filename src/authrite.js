const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')

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
  derivePrivateKey (serverIdentitiyKey, serverNonce) {
    return getPaymentPrivateKey({
      recipientPrivateKey: this.client.privateKey,
      senderPublicKey: serverIdentitiyKey,
      invoiceNumber: 'authrite message signature-' + this.client.nonce + ' ' + serverNonce,
      returnType: 'hex'
    })
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
    console.log('Server Response: ', serverResponse)
    if (serverResponse.authrite === AUTHRITE_VERSION && serverResponse.messageType === 'initialResponse') {
      // Validate server signature
      // 1. Obtain the public key
      const signingPublicKey = this.derivePublicKey(serverResponse.identityKey, serverResponse.nonce)
      // 2. Construct the message for verification
      const messageToVerify = this.client.nonce + serverResponse.nonce
      // 3. Verify the signature
      const signature = bsv.crypto.Signature.fromString(serverResponse.signature)
      console.log('Signature: ' + signature)
      console.log('Message to verify: ' + messageToVerify)
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
  async request (method, routePath, payload, headers) {
    // Check for server parameters
    if (!this.server.identityPublicKey || !this.server.nonce) {
      await this.getServerParameters()
    }
    // Create a request signature using client key, server key, client-generated nonce, and server nonce.
    const message = this.client.nonce + this.server.nonce
    const derivedClientPrivateKey = this.derivePrivateKey(this.server.identityPublicKey, this.server.nonce)
    const requestSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(message)),
      bsv.PrivateKey.fromHex(derivedClientPrivateKey)
    )
    // Send the signed Authrite request with the HTTP headers according to the specification.
    const response = await boomerang(
      method,
      this.server.baseUrl + routePath,
      {
        authrite: AUTHRITE_VERSION,
        identityKey: this.client.publicKey,
        nonce: this.client.nonce,
        certificates: this.client.certificates,
        payload,
        signature: requestSignature
      },
      headers
    )
    // TODO: Add error handling
    // When the server response comes back, validate the signature according to the specification.
    const signingPublicKey = this.derivePublicKey(this.server.identityPublicKey, response.nonce)
    // 2. Construct the message for verification
    const messageToVerify = this.client.nonce + response.nonce
    // 3. Verify the signature
    const signature = bsv.crypto.Signature.fromString(response.signature)
    console.log('Signature: ' + signature)
    console.log('Message to verify: ' + messageToVerify)
    const verified = bsv.crypto.ECDSA.verify(
      bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
      signature,
      bsv.PublicKey.fromString(signingPublicKey)
    )
    if (verified) {
      // TODO: figure out what to return
      return response.payload
    }
  }
}
module.exports = { Authrite }
