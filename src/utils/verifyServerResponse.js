const BabbageSDK = require('@babbage/sdk')
const { getPaymentAddress } = require('sendover')
const bsv = require('babbage-bsv')

/**
 * Verifies a server's response after the initial handshake has happened
 * @param {object} obj - all params given in an object
 * @param {string} obj.messageToVerify - the message signed to verify
 * @param {object} obj.headers - the authentication headers provided by the server
 * @param {string} obj.baseUrl - the baseUrl of the server
 * @param {string} obj.signingStrategy - specifies which signing strategy should be used
 * @param {object} obj.clients - the clients the current Authrite instance is interacting with
 * @param {object} obj.servers - the servers the current Authrite instance is interacting with
 * @param {string | buffer | undefined} [obj.clientPrivateKey] - clientPrivateKey to use for key derivation
 */
const verifyServerResponse = async ({
  messageToVerify,
  headers,
  baseUrl,
  signingStrategy,
  clients,
  servers,
  clientPrivateKey
}) => {
  // When the server response comes back, validate the signature according to the specification
  let signature, verified

  // Construct the message for verification
  // The client's initial nonce is used in combination with the server's random nonce for the keyID
  // Determine which signing strategy to use
  if (signingStrategy === 'Babbage') {
    signature = Buffer.from(headers['x-authrite-signature'], 'hex').toString('base64')
    verified = await BabbageSDK.verifySignature({
      data: Buffer.from(messageToVerify),
      signature,
      protocolID: [2, 'authrite message signature'],
      keyID: `${clients[baseUrl].nonce} ${headers['x-authrite-nonce']}`,
      counterparty: servers[baseUrl].identityPublicKey
    })
  } else {
    // Use the given client's private key as a signing strategy
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: clientPrivateKey,
      recipientPublicKey: servers[baseUrl].identityPublicKey,
      invoiceNumber: `2-authrite message signature-${clients[baseUrl].nonce} ${headers['x-authrite-nonce']}`,
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
  return verified
}
module.exports = verifyServerResponse
