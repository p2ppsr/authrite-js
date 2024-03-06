const bsv = require('babbage-bsv')
const sdk = require('@babbage/sdk-ts')
const { Authrite } = require('./authrite')

class AuthriteClient {
  /**
   * Since Authrite maintains a cache of certificates, it is often necessary to
   * share an Authrite instance across multiple client requests.
   *
   * This class wraps a single class static Authrite instance to
   * simplify applications that make multiple requests.
   *
   * Shares a common Authrite instance to allow caching for certificates.
   *
   * @param {String} serverUrl The baseUrl of the Server to which multiple Authrite requests are being made.
   * @param {object} authriteParams Optional constructor parameters for singleton Authrite instance.
   * @param {String} configId Optional shared instance identifier. One singleton is shared across all uses of same configId.
   * @returns {object} The new object. Fields are 'authrite' (shared Authrite instance) and 'serverURL' (constructor argument)
   * @constructor
   */
  constructor (serverURL, authriteParams = {}, configId = 'default') {
    // Authrite caches certificates for multiple clients.
    // For performance, there should be only one.
    if (!AuthriteClient.Authrite) AuthriteClient.Authrite = {}
    if (configId === 'default' && authriteParams?.clientPrivateKey) {
      configId = bsv.PrivateKey.fromHex(authriteParams.clientPrivateKey).publicKey.toString()
    }
    if (!AuthriteClient.Authrite[configId]) {
      AuthriteClient.Authrite[configId] = new Authrite(authriteParams)
    }

    this.authrite = AuthriteClient.Authrite[configId]
    this.serverURL = serverURL
    this.authriteParams = authriteParams
    this.configId = configId
  }

  /**
   * @public
   * Creates a new signed authrite request and returns the request's response body as result object.
   *
   * Error handling is simplified. If the response body has a status field with value 'error',
   * creates an Error object from response description,
   * adds response fields other than 'status' and 'description' to error object,
   * and throws the error object.
   *
   * @param {String} path concatenated to serverURL to yield full URL for this request
   * @param {object} body fields and values to be sent in body of this request
   * @returns {object} object constructed from body of response. UTF8 decoded. JSON.parse'd.
   */
  // NOTE: This does not currently support GET requests!!
  async createSignedRequest (path, body) {
    let result = await this.authrite.request(
      `${this.serverURL}${path}`,
      {
        body,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    result = JSON.parse(Buffer.from(result.body).toString('utf8'))
    if (typeof result === 'object' && result.status === 'error') {
      const e = new Error(result.description)
      Object
        .keys(result)
        .filter(x => x !== 'status' && x !== 'description')
        .forEach(x => { e[x] = result[x] })
      throw e
    }
    return result
  }

  /**
     * Creates a signed certificate by invoking the Babbage SDK createCertificate function.
     * On success, adds the new certificate to the cache maintained by the singleton authrite instance.
     * @param {Object} obj All parameters for this function are provided in an object
     * @param {string} obj.certificateType The type of certificate to create
     * @param {Object} obj.fieldObject The fields to add to the certificate
     * @param {string} obj.certifierUrl The URL of the certifier signing the certificate
     * @param {string} obj.certifierPublicKey The public identity key of the certifier signing the certificate
     * @returns {Promise<Object>} A signed certificate
     */
  async createCertificate ({
    certificateType,
    fieldObject,
    certifierUrl,
    certifierPublicKey
  }) {
    const certificate = await sdk.createCertificate({
      certificateType,
      fieldObject,
      certifierUrl,
      certifierPublicKey
    })
    this.authrite.addCertificate(certificate)
    return certificate
  }
}

module.exports = {
  AuthriteClient
}
