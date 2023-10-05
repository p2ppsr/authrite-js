const { getPaymentPrivateKey } = require('sendover')
const bsv = require('babbage-bsv')
const BabbageSDK = require('@babbage/sdk')

/**
 * Creates a valid ECDSA message signature to include in an Authrite request
 * @param {object} obj - all params given in an object
 * @param {string | buffer} obj.dataToSign - the data that should be signed with the derived private key
 * @param {string} obj.requestNonce - random data provided by the client
 * @param {string} obj.serverInitialNonce - random session data provided by the server
 * @param {string} [obj.clientPrivateKey] - optional private key to use as the signing strategy
 * @param {string} obj.serverPublicKey - the identity key of the server the request should be sent to
 */
const createRequestSignature = async ({
  dataToSign,
  requestNonce,
  serverInitialNonce,
  clientPrivateKey,
  serverPublicKey
}) => {
  let requestSignature

  // Support both the Babbage and private key signing strategies
  if (clientPrivateKey === undefined) {
    requestSignature = await BabbageSDK.createSignature({
      data: Buffer.from(dataToSign),
      protocolID: [2, 'authrite message signature'],
      keyID: `${requestNonce} ${serverInitialNonce}`,
      counterparty: serverPublicKey
    })

    // The request signature must be in hex
    requestSignature = Buffer.from(requestSignature).toString('hex')
  } else {
    const derivedClientPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: clientPrivateKey,
      senderPublicKey: serverPublicKey,
      invoiceNumber: `2-authrite message signature-${requestNonce} ${serverInitialNonce}`,
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
