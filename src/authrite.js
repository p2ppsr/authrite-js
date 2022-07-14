const boomerang = require('boomerang-http')
const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const BabbageSDK = require('@babbage/sdk')
// The correct versions of URL and fetch should be used
let fetch, URL
if (typeof window !== 'undefined') {
  fetch = typeof window.fetch !== 'undefined'
    ? window.fetch
    : require('node-fetch')
  URL = typeof window.URL !== 'undefined'
    ? window.URL
    : require('url').URL
} else {
  fetch = require('node-fetch')
  URL = require('url').URL
}

const AUTHRITE_VERSION = '0.1'

/**
   * The client requesting communication with the server
   * @private
   */
class Client {
  constructor () {
    this.nonce = crypto.randomBytes(32).toString('base64')
    this.certificates = []
  }
}

/**
   * The server with whom the client is establishing authenticated communication
   * @param {String} baseUrl The baseUrl of the Server
   * @param {String} identityPublicKey The identifier of the Server
   * @param {String} nonce A 256 bit number converted to a base64 string
   * @param {Array} certificates Certificate authorities of the Server
   * @param {Object} requestedCertificates Indicates certificates requested by Client
   * @private
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
   * Client-side API for establishing authenticated server communication
   * @public
   * @param {object} authrite All parameters are given in an object.
   * @param {String} authrite.clientPrivateKey The client's private key used for derivations
   * @param {String} authrite.initialRequestPath Initial request path for establishing a connection
   * @constructor
   */
  constructor ({
    clientPrivateKey,
    initialRequestPath = '/authrite/initialRequest'
  }) {
    // Determine the signing strategy to use
    if (clientPrivateKey) {
      this.signingStrategy = 'ClientPrivateKey'
      this.clientPrivateKey = clientPrivateKey
      this.clientPublicKey = bsv.PrivateKey.fromHex(clientPrivateKey).publicKey.toString() // TODO: plural or singular clients?
    } else {
      this.signingStrategy = 'Babbage'
      // The clientPublicKey will be retrieved from the SDK in the inital request
      this.clientPublicKey = null
    }
    this.initialRequestPath = initialRequestPath
    /*
      Servers and Clients are objects whose keys are base URLs and whose values are instances of the Server or Client class.
    */
    this.servers = {}
    this.clients = {}
  }

  // Fetch initial server parameters
  async getServerParameters (baseUrl) {
    this.clients[baseUrl] = new Client()
    this.servers[baseUrl] = new Server(baseUrl, null, null, [], [])
    // Retrieve the client's public identity key for the initial request
    // TODO: verify it gets returned in the correct format (hex?)
    if (!this.clientPublicKey && this.signingStrategy === 'Babbage') {
      this.clientPublicKey = await BabbageSDK.getPublicKey({ identityKey: true })
    }
    const serverResponse = await boomerang(
      'POST',
      baseUrl + this.initialRequestPath,
      {
        authrite: AUTHRITE_VERSION,
        messageType: 'initialRequest',
        identityKey: this.clientPublicKey,
        nonce: this.clients[baseUrl].nonce,
        requestedCertificates: this.servers[baseUrl].requestedCertificates // TODO: provide requested certificates
      }
    )
    if (
      serverResponse.authrite === AUTHRITE_VERSION &&
      serverResponse.messageType === 'initialResponse'
    ) {
      // Validate server signature
      let signature, verified
      // Construct the message for verification
      const messageToVerify = this.clients[baseUrl].nonce + serverResponse.nonce
      if (this.signingStrategy === 'Babbage') {
        // Create a signature using the BabbageSDK
        signature = await BabbageSDK.createSignature({
          data: Buffer.from(messageToVerify),
          protocolID: 'authrite message signature', // TODO: include security level
          keyID: `${this.clients[baseUrl].nonce} ${serverResponse.nonce}`,
          counterparty: serverResponse.identityKey
        })
        // Verify the signature created by the SDK
        verified = await BabbageSDK.verifySignature({
          data: Buffer.from(messageToVerify),
          signature: Buffer.from(signature).toString('base64'),
          protocolID: 'authrite message signature', // TODO: include security level
          keyID: `${this.clients[baseUrl].nonce} ${serverResponse.nonce}`
        })
      } else {
      // 1. Obtain the client's signing public key
        const signingPublicKey = getPaymentAddress({
          senderPrivateKey: this.clientPrivateKey,
          recipientPublicKey: serverResponse.identityKey,
          invoiceNumber: `authrite message signature-${this.clients[baseUrl].nonce} ${serverResponse.nonce}`,
          returnType: 'publicKey'
        })
        // 2. Verify the signature
        signature = bsv.crypto.Signature.fromString(serverResponse.signature)
        verified = bsv.crypto.ECDSA.verify(
          bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
          signature,
          bsv.PublicKey.fromString(signingPublicKey)
        )
      }
      // Determine if the signature was verified
      if (verified) {
        this.servers[baseUrl].identityPublicKey = serverResponse.identityKey
        this.servers[baseUrl].nonce = serverResponse.nonce
        this.servers[baseUrl].requestedCertificates = serverResponse.requestedCertificates // TODO: check certs
      } else {
        throw new Error('Unable to verify server signature!')
      }
    } else {
      throw new Error('Authrite version incompatible')
    }
  }

  /**
   * @public
   * Creates a new signed authrite request and returns the result
   * @param {String} requestUrl The URL to request on an Authrite-enabled server
   * @param {object} fetchConfig Config object passed to the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). The current version of Authrite only supports JSON structures for the fetch body. However, you can include a [Buffer](https://nodejs.org/api/buffer.html) as part of the json object.
   * @returns {object} The response object. Fields are 'status', 'headers' and 'body' (containing an ArrayBuffer of the HTTP response body)
   */
  async request (requestUrl, fetchConfig = {}) {
    // Extract baseUrl from URL
    const parsedUrl = new URL(requestUrl)
    if (!parsedUrl.host) {
      throw new Error('Invalid request URL!')
    }
    const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`
    // Check for server parameters
    if (
      !this.servers[baseUrl] ||
      !this.servers[baseUrl].identityPublicKey ||
      !this.servers[baseUrl].nonce
    ) {
      await this.getServerParameters(baseUrl)
    }
    // Make sure the fetchConfig body is formatted to the correct content type
    // TODO: Check fetchConfig.headers['Content-Type'] to support other data types
    if (!fetchConfig.headers) {
      fetchConfig.headers = {}
    }
    let dataToSign
    // Check if we should sign the requestURL instead of the body
    // The fetch API POST request method defaults to 'GET'
    if (!fetchConfig.method) {
      fetchConfig.method = 'GET'
    }
    if (fetchConfig.method === 'GET' || fetchConfig.method === 'HEAD') {
      dataToSign = requestUrl
    } else {
      // The fetch API POST request body defaults to '{}'
      if (!fetchConfig.body) {
        fetchConfig.body = '{}'
      } else {
        fetchConfig.body = typeof (fetchConfig.body) === 'string' ? fetchConfig.body : JSON.stringify(fetchConfig.body)
      }
      dataToSign = fetchConfig.body
      if (!fetchConfig.headers['Content-Type']) {
        fetchConfig.headers['Content-Type'] = 'application/json'
      }
    }
    // If the request body is empty, sign the url instead
    if (!dataToSign) {
      dataToSign = requestUrl
    }

    // For subsequent requests,
    // we want to generates a new requestNonce
    // and use it together with the server’s initialNonce for key derivation
    const requestNonce = crypto.randomBytes(32).toString('base64')
    let requestSignature
    if (this.signingStrategy === 'Babbage') {
      requestSignature = await BabbageSDK.createSignature({
        data: Buffer.from(dataToSign),
        protocolID: 'authrite message signature', // TODO: add security level
        keyID: `${requestNonce} ${this.servers[baseUrl].nonce}`,
        counterparty: this.servers[baseUrl].identityPublicKey
      })
      // The request signature must be in hex
      requestSignature = Buffer.from(requestSignature).toString('hex') // TODO: Test the response from createSignature of the SDK
    } else {
      const derivedClientPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: this.clientPrivateKey,
        senderPublicKey: this.servers[baseUrl].identityPublicKey,
        invoiceNumber: `authrite message signature-${requestNonce} ${this.servers[baseUrl].nonce}`,
        returnType: 'wif'
      })
      // Create a request signature
      requestSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
        bsv.PrivateKey.fromWIF(derivedClientPrivateKey)
      )
      requestSignature = requestSignature.toString()
    }

    // Send the signed Authrite fetch request with the HTTP headers according to the specification
    const response = await fetch(
      requestUrl,
      {
        ...fetchConfig,
        headers: {
          ...fetchConfig.headers,
          'X-Authrite': AUTHRITE_VERSION,
          'X-Authrite-Identity-Key': this.clientPublicKey,
          'X-Authrite-Nonce': requestNonce,
          'X-Authrite-YourNonce': this.servers[baseUrl].nonce,
          'X-Authrite-Certificates': this.clients[baseUrl].certificates,
          'X-Authrite-Signature': requestSignature
        }
      }
    )
    // When the server response comes back, validate the signature according to the specification
    let signature, verified
    // Construct the message for verification
    const messageToVerify = await response.arrayBuffer()
    // Determine which signing strategy to use
    if (this.signingStrategy === 'Babbage') {
      signature = await BabbageSDK.createSignature({
        data: Buffer.from(messageToVerify.data),
        protocolID: 'authrite message signature',
        keyID: `${requestNonce} ${response.headers.get('X-Authrite-Nonce')}`,
        counterparty: this.servers[baseUrl].identityPublicKey
      })
      verified = await BabbageSDK.verifySignature({
        data: Buffer.from(messageToVerify),
        signature: Buffer.from(signature).toString('base64'),
        protocolID: 'authrite message signature',
        keyID: `${requestNonce} ${response.headers.get('X-Authrite-Nonce')}`,
        counterparty: this.servers[baseUrl].identityPublicKey
      })
    } else {
      // Use the given client's private key as a signing strategy
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.clientPrivateKey,
        recipientPublicKey: this.servers[baseUrl].identityPublicKey,
        invoiceNumber: 'authrite message signature-' + requestNonce + ' ' + response.headers.get('X-Authrite-Nonce'),
        returnType: 'publicKey'
      })
      // Create and verify the signature
      signature = bsv.crypto.Signature.fromString(
        response.headers.get('x-authrite-signature')
      )
      verified = bsv.crypto.ECDSA.verify(
        bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
        signature,
        bsv.PublicKey.fromString(signingPublicKey)
      )
    }
    if (verified) {
      return {
        status: response.status,
        headers: response.headers,
        body: messageToVerify
      }
    } else {
      throw new Error('Unable to verify Authrite server response signature!')
    }
  }
}

module.exports = { Authrite }
