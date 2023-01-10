const boomerang = require('boomerang-http')
const bsv = require('babbage-bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const BabbageSDK = require('@babbage/sdk')
const authriteUtils = require('authrite-utils')

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
      if (!authriteUtils.verifyCertificateSignature(cert)) {
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
    // Check serverResponse for errors
    if (serverResponse.status === 'error') {
      this.servers[baseUrl].updating = false
      const e = new Error(`${serverResponse.code} --> ${serverResponse.description} Please check the Authrite baseURL and initial request path config`)
      e.code = 'ERR_INVALID_SERVER_REQUEST'
      throw e
    }
    if (
      serverResponse.authrite !== AUTHRITE_VERSION ||
      serverResponse.messageType !== 'initialResponse'
    ) {
      this.servers[baseUrl].updating = false
      const e = new Error('Authrite version incompatible')
      e.code = 'ERR_INVALID_AUTHRITE_VERSION'
      throw e
    }
    // Validate server signature
    let signature, verified
    // Construct the message for verification
    const messageToVerify = this.clients[baseUrl].nonce + serverResponse.nonce
    if (this.signingStrategy === 'Babbage') {
      signature = Buffer.from(serverResponse.signature, 'hex').toString('base64')
      // Verify the signature created by the SDK
      verified = await BabbageSDK.verifySignature({
        data: Buffer.from(messageToVerify),
        signature,
        protocolID: [2, 'authrite message signature'],
        keyID: `${this.clients[baseUrl].nonce} ${serverResponse.nonce}`,
        counterparty: serverResponse.identityKey
      })
    } else {
    // 1. Obtain the client's signing public key
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.clientPrivateKey,
        recipientPublicKey: serverResponse.identityKey,
        invoiceNumber: `2-authrite message signature-${this.clients[baseUrl].nonce} ${serverResponse.nonce}`,
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
    if (!verified) {
      this.servers[baseUrl].updating = false
      const e = new Error('Unable to verify server signature!')
      e.code = 'ERR_INVALID_SIGNATURE'
      throw e
    }
    this.servers[baseUrl].identityPublicKey = serverResponse.identityKey
    this.servers[baseUrl].nonce = serverResponse.nonce

    // Check certificates were requested, and that the client is using Babbage as the signing strategy
    if (serverResponse.requestedCertificates.certifiers && serverResponse.requestedCertificates.certifiers.length !== 0 && this.signingStrategy === 'Babbage') {
      // Find matching certificates
      let matchingCertificates = await BabbageSDK.getCertificates({
        certifiers: serverResponse.requestedCertificates.certifiers,
        types: serverResponse.requestedCertificates.types
      })

      // IF the getCertificates function returns any certificates
      // THEN they are added to the this.certificates within the Authrite client.
      if (matchingCertificates.length !== 0) {
        // Update certs to contain a keyring property
        matchingCertificates = matchingCertificates.map(cert => {
          cert.keyrings = {}
          return cert
        })
        // Check if cert is already added to this.certificates to prevent duplicates
        // Note: Valid certificates with identical signatures are always identical
        matchingCertificates.forEach(cert => {
          let duplicate = false
          this.certificates.every(existingCert => {
            if (existingCert.signature === cert.signature) {
              // skip the duplicate cert found!
              duplicate = true
              return false
            }
            return true
          })
          if (!duplicate) {
            this.certificates.push(cert)
            duplicate = false
          }
        })
      }
    }
    this.servers[baseUrl].requestedCertificates = serverResponse.requestedCertificates
    this.servers[baseUrl].updating = false
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
    // When the server response comes back, validate the signature according to the specification
    let signature, verified
    // Construct the message for verification
    const messageToVerify = await response.arrayBuffer()
    // Determine which signing strategy to use
    if (this.signingStrategy === 'Babbage') {
      signature = Buffer.from(response.headers.get('x-authrite-signature'), 'hex').toString('base64')
      verified = await BabbageSDK.verifySignature({
        data: Buffer.from(messageToVerify),
        signature,
        protocolID: [2, 'authrite message signature'],
        keyID: `${requestNonce} ${response.headers.get('X-Authrite-Nonce')}`,
        counterparty: this.servers[baseUrl].identityPublicKey
      })
    } else {
      // Use the given client's private key as a signing strategy
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: this.clientPrivateKey,
        recipientPublicKey: this.servers[baseUrl].identityPublicKey,
        invoiceNumber: '2-authrite message signature-' + requestNonce + ' ' + response.headers.get('X-Authrite-Nonce'),
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
    if (!verified) {
      const e = new Error(
        'Unable to verify Authrite server response signature!'
      )
      e.code = 'ERR_INVALID_SIGNATURE'
      throw e
    }
    return {
      status: response.status,
      headers: response.headers,
      body: messageToVerify
    }
  }

  /**
   * @public
   * Adds a newly created certificate to the cache
   * @param {object} certificate Certificate produced by createCertificate to be added to the cache.
   */
  async addCertificate (certificate) {
    if (!this.certificates.every(c => c.signature !== certificate.signature))
      // Don't add if duplicate
      return

    this.certificates.push({...certificate, keyrings: {}})
  }
}

module.exports = {
  Authrite,
  utils
}
