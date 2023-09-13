const boomerang = require('boomerang-http')
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const { getPaymentPrivateKey } = require('sendover')
const BabbageSDK = require('@babbage/sdk')
const { verifyCertificateSignature } = require('authrite-utils')
const io = require('socket.io-client')
const verifyServerSignature = require('./utils/verifyServerSignature')
const verifyServerResponse = require('./utils/verifyServerResponse')

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
    this.updating = true
  }
}

class Authrite {
  /**
   * Client-side API for establishing authenticated server communication
   * @public
   * @param {object} authrite All parameters are given in an object.
   * @param {String} authrite.clientPrivateKey The client's private key used for derivations
   * @param {String} authrite.initialRequestPath Initial request path for establishing a connection
   * @param {Array} authrite.certificates Provided certificates from the client
   * @constructor
   */
  constructor ({
    clientPrivateKey,
    initialRequestPath = '/authrite/initialRequest',
    signingStrategy = 'Babbage',
    certificates = []
  } = {}) {
    // Determine the signing strategy to use
    if (clientPrivateKey) {
      if (
        typeof clientPrivateKey === 'string' &&
        clientPrivateKey.length !== 64
      ) {
        const e = new Error('Please provide a valid client private key!')
        e.code = 'ERR_INVALID_CLIENT_PRIVATE_KEY'
        throw e
      }
      this.signingStrategy = 'ClientPrivateKey'
      this.clientPrivateKey = clientPrivateKey
      this.clientPublicKey = bsv.PrivateKey
        .fromHex(clientPrivateKey)
        .publicKey.toString()
    } else {
      this.signingStrategy = signingStrategy
      // The clientPublicKey will be retrieved from the SDK in the inital request
      this.clientPublicKey = null
    }
    this.initialRequestPath = initialRequestPath
    /*
      Servers and Clients are objects whose keys are base URLs and whose values are instances of the Server or Client class.
    */
    this.servers = {}
    this.clients = {}
    // Validate provided certificates
    certificates.forEach(cert => {
      if (!verifyCertificateSignature(cert)) {
        const e = new Error('Certificate signature verification failed!')
        e.code = 'ERR_CERT_SIG_VERIFICATION_FAILED'
        throw e
      }
      if (typeof cert.keyrings !== 'object') {
        cert.keyrings = {}
      }
    })
    this.certificates = certificates
  }

  // Fetch initial server parameters
  async getServerParameters (baseUrl) {
    this.clients[baseUrl] = new Client()
    this.servers[baseUrl] = new Server(baseUrl, null, null, [], [])
    // Retrieve the client's public identity key for the initial request
    if (!this.clientPublicKey && this.signingStrategy === 'Babbage') {
      this.clientPublicKey = await BabbageSDK.getPublicKey({
        identityKey: true
      })
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
    // Note: are clients and servers passed by references or copy?
    await verifyServerSignature({
      authriteVersion: AUTHRITE_VERSION,
      baseUrl,
      signingStrategy: this.signingStrategy,
      clientPrivateKey: this.clientPrivateKey,
      clients: this.clients,
      servers: this.servers,
      serverResponse,
      certificates: this.servers[baseUrl].requestedCertificates // Verify this is expected
    })
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
      const e = new Error('Invalid request URL!')
      e.code = 'ERR_INVALID_URL'
      throw e
    }
    const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`
    // Check for server parameters
    if (this.servers[baseUrl] && this.servers[baseUrl].updating) {
      while (this.servers[baseUrl].updating) {
        await new Promise(resolve => setTimeout(resolve, 100))
      }
    }
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
        protocolID: [2, 'authrite message signature'],
        keyID: `${requestNonce} ${this.servers[baseUrl].nonce}`,
        counterparty: this.servers[baseUrl].identityPublicKey
      })
      // The request signature must be in hex
      requestSignature = Buffer.from(requestSignature).toString('hex')
    } else {
      const derivedClientPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: this.clientPrivateKey,
        senderPublicKey: this.servers[baseUrl].identityPublicKey,
        invoiceNumber: `2-authrite message signature-${requestNonce} ${this.servers[baseUrl].nonce}`,
        returnType: 'wif'
      })
      // Create a request signature
      requestSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(dataToSign)),
        bsv.PrivateKey.fromWIF(derivedClientPrivateKey)
      )
      requestSignature = requestSignature.toString()
    }

    // Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested.
    const requestedCerts = this.servers[baseUrl].requestedCertificates
    let certificatesToInclude = this.certificates.filter(cert =>
      requestedCerts.certifiers.includes(cert.certifier) &&
      Object.keys(requestedCerts.types).includes(cert.type)
    )

    await Promise.all(certificatesToInclude.map(async cert => {
      // Check if a keyring exists for this server/verifier.
      const verifierKeyring = cert.keyrings[this.servers[baseUrl].identityPublicKey]
      const requestedFields = this.servers[baseUrl].requestedCertificates.types[cert.type]

      // IF an existing keyring has been found, compare the list of fields from the keyring with the list of fields this server is requesting for this certificate type.
      // TODO: Consider refactoring array comparison.
      if (
        !verifierKeyring ||
        JSON.stringify(Object.keys(verifierKeyring)) !==
        JSON.stringify(requestedFields)
      ) {
        // If there are differences, or no keyring, SDK proveCertificate function generates a new keyring for this verifier containing only the verifier’s requested fields.
        // Ensure Babbage signing strategy is used
        if (this.signingStrategy !== 'Babbage') {
          const e = new Error('No valid keyring, or method for obtaining keyring, for this certificate and verifier!')
          e.code = 'ERR_NO_CERT_PROOF_STRATEGY'
          throw e
        }
        const { keyring } = await BabbageSDK.proveCertificate({
          certificate: {
            fields: cert.fields,
            serialNumber: cert.serialNumber,
            validationKey: cert.validationKey,
            certifier: cert.certifier,
            subject: cert.subject,
            type: cert.type,
            revocationOutpoint: cert.revocationOutpoint,
            signature: cert.signature
          },
          fieldsToReveal: requestedFields,
          verifierPublicIdentityKey: this.servers[baseUrl].identityPublicKey
        })
        // Save the keyring for this verifier
        cert.keyrings[this.servers[baseUrl].identityPublicKey] = keyring
      }
      cert.keyring = cert.keyrings[this.servers[baseUrl].identityPublicKey]
    }))

    // Remove all extra from the certificates
    certificatesToInclude = certificatesToInclude.map(cert => ({
      fields: cert.fields,
      serialNumber: cert.serialNumber,
      validationKey: cert.validationKey,
      certifier: cert.certifier,
      subject: cert.subject,
      type: cert.type,
      revocationOutpoint: cert.revocationOutpoint,
      signature: cert.signature,
      keyring: cert.keyring
    }))

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
          'X-Authrite-Certificates': JSON.stringify(certificatesToInclude),
          'X-Authrite-Signature': requestSignature
        }
      }
    )
    const messageToVerify = await response.arrayBuffer()

    // Parse out response headers
    const headers = {}
    response.headers.forEach((value, name) => {
      headers[name] = value
    })

    await verifyServerResponse({
      messageToVerify,
      headers,
      requestNonce,
      baseUrl,
      signingStrategy: this.signingStrategy,
      servers: this.servers,
      clientPrivateKey: this.clientPrivateKey
    })

    return {
      status: response.status,
      headers: response.headers,
      body: messageToVerify,
      json: async () => {
        return JSON.parse(Buffer.from(messageToVerify).toString('utf8'))
      }
    }
  }

  /**
   * Support initializing a socket connection to a server
   * @param {*} connectionUrl
   * @param {*} config
   */
  async connect (connectionUrl, config = {}) {
    this.clients[connectionUrl] = new Client()
    this.servers[connectionUrl] = new Server(connectionUrl, null, null, [], [])
    // Retrieve the client's public identity key for the initial request
    if (!this.clientPublicKey && this.signingStrategy === 'Babbage') {
      this.clientPublicKey = await BabbageSDK.getPublicKey({
        identityKey: true
      })
    }

    // Handle the initial request
    this.socket = io.connect(connectionUrl, {
      extraHeaders: {
        'x-authrite': AUTHRITE_VERSION,
        'x-message-type': 'initialRequest',
        'x-authrite-identity-key': this.clientPublicKey,
        'x-authrite-nonce': this.clients[connectionUrl].nonce,
        'x-authrite-certificates': this.servers[connectionUrl].requestedCertificates // TODO: provide requested certificates
      }
    })

    this.socket.on('validationResponse', async (serverResponse) => {
      console.log('Server says:', serverResponse)
      this.serverPublicKey = serverResponse.serverPublicKey

      // Note: potential to hang while waiting...
      await verifyServerSignature({
        authriteVersion: AUTHRITE_VERSION,
        baseUrl: connectionUrl,
        signingStrategy: this.signingStrategy,
        clientPrivateKey: this.clientPrivateKey,
        clients: this.clients,
        servers: this.servers,
        serverResponse,
        certificates: this.certificates
      })
      console.log('Server initial response verified!')
    })

    this.socket.on('serverResponse', async (data) => {
      const baseUrl = 'http://localhost:4000'
      await verifyServerResponse(
        'test',
        data.headers,
        this.clients[baseUrl].nonce,
        baseUrl,
        this.signingStrategy,
        this.servers,
        this.clientPrivateKey
      )
      console.log('Server response verified!')
    })

    // Return the current Authrite instance for direct access
    return this
  }

  async emit (event, data) {
    const baseUrl = 'http://localhost:4000'
    this.clients[baseUrl].nonce = crypto.randomBytes(32).toString('base64')
    // Note: does the server initial nonce need to be saved?

    let requestSignature = await BabbageSDK.createSignature({
      data: Buffer.from('test'),
      protocolID: [2, 'authrite message signature'],
      keyID: `${this.clients[baseUrl].nonce} ${this.servers[baseUrl].nonce}`,
      counterparty: this.servers[baseUrl].identityPublicKey
    })
    // The request signature must be in hex
    requestSignature = Buffer.from(requestSignature).toString('hex')

    this.socket.emit(event, {
      data,
      headers: {
        'x-authrite-identity-key': this.clientPublicKey,
        'x-authrite-nonce': this.clients[baseUrl].nonce,
        'x-authrite-yournonce': this.servers[baseUrl].nonce,
        'x-authrite-signature': requestSignature
      }
    })
  }

  /**
   * @public
   * Adds a newly created certificate to the cache
   * @param {object} certificate Certificate produced by createCertificate to be added to the cache.
   */
  async addCertificate (certificate) {
    // Don't add if duplicate
    if (!this.certificates.every(c => c.signature !== certificate.signature)) {
      return
    }

    this.certificates.push({ ...certificate, keyrings: {} })
  }
}

module.exports = {
  Authrite
}
