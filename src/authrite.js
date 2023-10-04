const boomerang = require('boomerang-http')
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const BabbageSDK = require('@babbage/sdk')
const { verifyCertificateSignature } = require('authrite-utils')
const io = require('socket.io-client')
const verifyServerInitialResponse = require('./utils/verifyServerInitialResponse')
const verifyServerResponse = require('./utils/verifyServerResponse')
const getCertificatesToInclude = require('./utils/getCertificatesToInclude')
const getRequestAuthHeaders = require('./utils/getRequestAuthHeaders')
const createRequestSignature = require('./utils/createRequestSignature')

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

const AUTHRITE_VERSION = '0.2'

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
      // The clientPublicKey will be retrieved from the SDK in the initial request
      this.clientPublicKey = null
    }
    this.initialRequestPath = initialRequestPath

    // Servers and Clients are objects whose keys are base URLs and whose values are instances of the Server or Client class.
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

    // Send an initial request to the server
    const serverResponse = await boomerang(
      'POST',
      baseUrl + this.initialRequestPath,
      {
        authrite: AUTHRITE_VERSION,
        messageType: 'initialRequest',
        identityKey: this.clientPublicKey,
        nonce: this.clients[baseUrl].nonce,
        requestedCertificates: this.servers[baseUrl].requestedCertificates
      }
    )

    // Verify the server's initial response
    await verifyServerInitialResponse({
      authriteVersion: AUTHRITE_VERSION,
      baseUrl,
      signingStrategy: this.signingStrategy,
      clientPrivateKey: this.clientPrivateKey,
      clients: this.clients,
      servers: this.servers,
      serverResponse,
      certificates: this.certificates
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
    // we want to generates a new requestNonce and use it together with the server’s initialNonce for key derivation
    const requestNonce = crypto.randomBytes(32).toString('base64')
    const requestSignature = await createRequestSignature({ dataToSign, requestNonce, baseUrl })

    // Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested.
    const certificatesToInclude = await getCertificatesToInclude({
      signingStrategy: this.signingStrategy,
      baseUrl,
      servers: this.servers,
      certificates: this.certificates
    })

    // Get auth headers to be verified by the server
    const authHeaders = await getRequestAuthHeaders({
      authriteVersion: AUTHRITE_VERSION,
      clientPublicKey: this.clientPublicKey,
      requestNonce,
      clientInitialNonce: this.clients[baseUrl].nonce,
      serverInitialNonce: this.servers[baseUrl].nonce,
      requestSignature,
      certificatesToInclude: JSON.stringify(certificatesToInclude)
    })

    // Send the signed Authrite fetch request with the HTTP headers according to the specification
    const response = await fetch(
      requestUrl,
      {
        ...fetchConfig,
        headers: {
          ...fetchConfig.headers,
          ...authHeaders
        }
      }
    )
    const messageToVerify = await response.arrayBuffer()

    // Handle route not found errors
    if (response.status === 404) {
      const e = new Error(`The requested route at ${requestUrl} was not found!`)
      e.code = 'ERR_NOT_FOUND'
      throw e
    }

    // Parse out response headers
    const headers = response.headers
    response.headers.forEach((value, name) => {
      headers[name] = value
    })

    // Make sure this is a valid Authrite response with the required headers
    // If the requested route didn't exist, the headers may be missing
    if (!headers || !headers['x-authrite']) {
      const e = new Error('Missing required Authrite headers!')
      e.code = 'ERR_MISSING_AUTHRITE_HEADERS'
      throw e
    }

    // Make sure the server properly authenticates itself
    const verified = await verifyServerResponse({
      messageToVerify,
      headers,
      baseUrl,
      signingStrategy: this.signingStrategy,
      clients: this.clients,
      servers: this.servers,
      clientPrivateKey: this.clientPrivateKey
    })

    // Throw an error if the signature verification fails
    if (!verified) {
      const e = new Error('Unable to verify Authrite server response signature!')
      e.code = 'ERR_INVALID_SIGNATURE'
      throw e
    }

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
   * Currently implemented as a drop-in replacement for the socket.io wrapper of WebSockets
   * @param {string} connectionUrl - the url of the server to connect to over web sockets
   * @param {object} config - standard socket.io configuration param
   */
  async connect (connectionUrl, config = {}) {
    this.clients[connectionUrl] = new Client()
    this.servers[connectionUrl] = new Server(connectionUrl, null, null, [], [])

    // Note: How do I know which server I am connection to over web sockets
    // when the on or emit functions are invoked?
    // Temp Solution
    this.socketConnectionUrl = connectionUrl

    // Retrieve the client's public identity key for the initial request
    if (!this.clientPublicKey && this.signingStrategy === 'Babbage') {
      this.clientPublicKey = await BabbageSDK.getPublicKey({
        identityKey: true
      })
    }

    // Handle the initial request
    this.socket = io.connect(this.socketConnectionUrl, {
      ...config,
      extraHeaders: {
        'x-authrite': AUTHRITE_VERSION,
        'x-message-type': 'initialRequest',
        'x-authrite-identity-key': this.clientPublicKey,
        'x-authrite-nonce': this.clients[this.socketConnectionUrl].nonce,
        'x-authrite-certificates': this.servers[this.socketConnectionUrl].requestedCertificates
      }
    })

    // Log any error's returned by the socket middleware
    this.socket.on('connect_error', (err) => {
      console.error(err)
      // TODO: Test connection errors
      if (err instanceof Error) {
        throw err
      }
    })

    // Handle custom thrown errors
    this.socket.on('error', (msg) => {
      console.error(msg)
      const errMsg = msg.data
      const error = new Error(errMsg.description)
      error.code = errMsg.code
      throw error
    })

    // Validate the server's initial response
    this.socket.on('validationResponse', async (serverResponse) => {
      console.log('Server says:', serverResponse)
      // Note: error handling required here on response?
      // TODO: Test response with errors
      this.serverPublicKey = serverResponse.serverPublicKey

      // Note: potential to hang while waiting...
      await verifyServerInitialResponse({
        authriteVersion: AUTHRITE_VERSION,
        baseUrl: this.socketConnectionUrl,
        signingStrategy: this.signingStrategy,
        clientPrivateKey: this.clientPrivateKey,
        clients: this.clients,
        servers: this.servers,
        serverResponse,
        certificates: this.certificates
      })
      console.log('Server initial response verified!')
    })

    // Return the current Authrite instance for direct access
    return this
  }

  on (event, callback) {
    if (!this.socket) {
      const e = new Error('You must first configure a socket connection!')
      e.code = 'ERR_MISSING_SOCKET'
      throw e
    }
    // Define a custom wrapped callback to authenticate headers provided
    const wrappedCallback = async (body) => {
      // Check if this is a custom or system call
      if (body && body.data && body.headers) {
      // Call the helper auth function
        await verifyServerResponse({
          messageToVerify: JSON.stringify(body.data),
          headers: body.headers,
          baseUrl: this.socketConnectionUrl,
          signingStrategy: this.signingStrategy,
          clients: this.clients,
          servers: this.servers,
          clientPrivateKey: this.clientPrivateKey
        })
        // Invoke the expected inner callback function (minus the headers)
        callback(body.data)
      } else {
        callback(body)
      }
    }
    // Call the base socket on function with modified callback
    this.socket.on(event, wrappedCallback)
  }

  async emit (event, data) {
    const requestNonce = crypto.randomBytes(32).toString('base64')

    // Create a request signature over the data to emit
    const requestSignature = await createRequestSignature({ dataToSign: JSON.stringify(data), requestNonce, baseUrl: this.socketConnectionUrl })

    // Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested.
    const certificatesToInclude = await getCertificatesToInclude({
      signingStrategy: this.signingStrategy,
      baseUrl: this.socketConnectionUrl,
      servers: this.servers,
      certificates: this.certificates
    })

    // Get auth headers to be verified by the server
    const authHeaders = await getRequestAuthHeaders({
      authriteVersion: AUTHRITE_VERSION,
      clientPublicKey: this.clientPublicKey,
      requestNonce,
      clientInitialNonce: this.clients[this.socketConnectionUrl].nonce,
      serverInitialNonce: this.servers[this.socketConnectionUrl].nonce,
      requestSignature,
      certificatesToInclude: JSON.stringify(certificatesToInclude)
    })

    // Send off the original emit request + auth headers
    this.socket.emit(event, {
      data,
      headers: authHeaders
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
