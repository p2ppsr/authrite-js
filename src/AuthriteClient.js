const sdk = require('@babbage/sdk')
const { Authrite } = require('authrite-js')

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
   * @returns {object} The new object. Fields are 'authrite' (shared Authrite instance) and 'serverURL' (constructor argument)
   * @constructor
   */
    constructor(serverURL) {
        // Authrite caches certificates for multiple clients.
        // For performance, there should be only one.
        if (!AuthriteClient.Authrite) {
            AuthriteClient.Authrite = new Authrite()
        }

        this.authrite = AuthriteClient.Authrite
        this.serverURL = serverURL
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
    async createSignedRequest(path, body) {
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
    async createCertificate({
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
