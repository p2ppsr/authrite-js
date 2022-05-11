const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const { getDataToSign, formatFetchConfigBody } = require('./utils/processFetchConfig')
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
   * Client Constructor
   * @param {String} privateKey associated with the identityPublicKey
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
   * Server Constructor
   * @param {String} baseUrl The baseUrl of the Server
   * @param {String} identityPublicKey The identifier of the Server
   * @param {String} nonce A 256 bit number converted to a base64 string
   * @param {Array} certificates Certificate authorities of the Server
   * @param {Object} requestedCertificates Indicates certificates requested by Client
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
    * @param {object} authrite
    * @param {String} authrite.baseUrl The server baseUrl we want to talk to
    * @param {String} authrite.clientPrivateKey The client's private key used for derivations
    * @param {String} authrite.initialRequestPath Initial request path for establishing a connection (defaults to '/authrite/initialRequest')
    * @param {String} authrite.initialRequestMethod Initial request method (defaults to 'POST')
    */
  constructor ({
    baseUrl,
    clientPrivateKey,
    initialRequestPath = '/authrite/initialRequest',
    initialRequestMethod = 'POST'
  }) {
    this.initialRequestPath = initialRequestPath
    this.initalRequestMethod = initialRequestMethod
    if (!clientPrivateKey) throw new Error('Please provide a valid client private key!')
    if (!baseUrl) throw new Error('Please provide a valid base server URL!')
    this.client = new Client(clientPrivateKey)
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
    if (
      serverResponse.authrite === AUTHRITE_VERSION &&
      serverResponse.messageType === 'initialResponse'
    ) {
      // Validate server signature
      // 1. Obtain the public key
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.client.privateKey,
        recipientPublicKey: serverResponse.identityKey,
        invoiceNumber: `authrite message signature-${this.client.nonce} ${serverResponse.nonce}`,
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
   * Creates a new signed authrite request
   * @param {String} routePath The path on the server to request
   * @param {object} fetchConfig Config object passed to the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)
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
    let response
    try {
      // Default method and header for a request containing a body
      if (fetchConfig.body) {
        fetchConfig.method ??= 'POST'
        fetchConfig.headers ??= {
          'Content-Type': 'application/json'
        }
        // Make sure the fetchConfig body is formatted to the content type
        fetchConfig.body = formatFetchConfigBody(fetchConfig, fetchConfig.headers['Content-Type'])
      }
      // Check if a fetchConfig has data that was passed in
      const dataToSign = getDataToSign(fetchConfig, this.server.baseUrl + routePath)
      const requestSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
        bsv.PrivateKey.fromHex(derivedClientPrivateKey)
      )
      // Send the signed Authrite fetch request with the HTTP headers according to the specification
      // The user can specify any type of content, pass in the correctly formated body,
      // and the node fetch API will try to handle it automatically.
      // [FetchAPI Body](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#body)
      response = await fetch(
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
            'X-Authrite-Signature': requestSignature.toString()
          }
        }
      )
    } catch (error) {
      throw new Error(`FetchConfig not configured correctly! ErrorMessage: ${error.message}`)
    }
    if (!response) {
      throw new Error('Failed to get response from server!')
    }
    try {
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
    } catch (error) {
      throw new Error('Server could not find Authrite headers in request from client!')
    }
  }
}
module.exports = { Authrite }
