const { getPaymentPrivateKey } = require('sendover')
const bsv = require('babbage-bsv')
const BabbageSDK = require('@babbage/sdk')

/**
 * Creates a valid ECDSA signature to include in an Authrite request
 * @param {object} obj - all params given in an object
 * @param {string | buffer} obj.dataToSign - the data that should be signed with the derived private key
 * @param {string} obj.requestNonce - random data provided by the client
 * @param {string} obj.baseUrl - the URL of the server the request is being sent to
 */
const createRequestSignature = async ({ dataToSign, requestNonce, baseUrl }) => {
  let requestSignature

  // Support both the Babbage and private key signing strategies
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
  return requestSignature
}
module.exports = createRequestSignature
