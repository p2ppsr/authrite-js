const BabbageSDK = require('@babbage/sdk')
const { getPaymentAddress } = require('sendover')
const bsv = require('babbage-bsv')

const verifyServerResponse = async (messageToVerify, headers, requestNonce, baseUrl, signingStrategy, servers, clientPrivateKey) => {
  // When the server response comes back, validate the signature according to the specification
  let signature, verified
  // Construct the message for verification
  // Determine which signing strategy to use
  if (signingStrategy === 'Babbage') {
    signature = Buffer.from(headers['x-authrite-signature'], 'hex').toString('base64')
    verified = await BabbageSDK.verifySignature({
      data: Buffer.from(messageToVerify),
      signature,
      protocolID: [2, 'authrite message signature'],
      keyID: `${requestNonce} ${headers['x-authrite-nonce']}`,
      counterparty: servers[baseUrl].identityPublicKey
    })
  } else {
    // Use the given client's private key as a signing strategy
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: clientPrivateKey,
      recipientPublicKey: servers[baseUrl].identityPublicKey,
      invoiceNumber: '2-authrite message signature-' + requestNonce + ' ' + headers['x-authrite-nonce'],
      returnType: 'publicKey'
    })
    // Create and verify the signature
    signature = bsv.crypto.Signature.fromString(
      headers['x-authrite-signature']
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
}
module.exports = verifyServerResponse
