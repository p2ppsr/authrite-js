const { getPaymentAddress } = require('sendover')
const BabbageSDK = require('@babbage/sdk')
const bsv = require('babbage-bsv')

/**
 * Verifies a server's initial response as part of the initial handshake
 * @param {object} obj - all params given in an object
 * @param {string} obj.authriteVersion - the current version of Authrite being used by the server
 * @param {string} obj.baseUrl - the baseUrl of the server
 * @param {string} obj.signingStrategy - specifies which signing strategy should be used
 * @param {string | buffer | undefined} [obj.clientPrivateKey] - clientPrivateKey to use for key derivation
 * @param {object} obj.clients - object whose keys are base URLs and whose values are instances of the Client class
 * @param {object} obj.servers - object whose keys are base URLs and whose values are instances of the Server class
 * @param {object} obj.serverResponse - contains the server's response including the required authentication data
 * @param {Array}  obj.certificates - the current available certificates
*/
const verifyServerInitialResponse = async ({
  authriteVersion,
  baseUrl,
  signingStrategy,
  clientPrivateKey,
  clients,
  servers,
  serverResponse,
  certificates
}) => {
  // Check serverResponse for errors
  if (serverResponse.status === 'error') {
    servers[baseUrl].updating = false
    const e = new Error(`${serverResponse.code} --> ${serverResponse.description} Please check the Authrite baseURL and initial request path config`)
    e.code = 'ERR_INVALID_SERVER_REQUEST'
    throw e
  }

  // Validate the required data is provided
  if (serverResponse.identityKey === undefined) {
    const e = new Error('Server initial response did not provided an identity public key!')
    e.code = 'ERR_MISSING_SERVER_IDENTITY_KEY'
    throw e
  }
  if (
    serverResponse.authrite !== authriteVersion ||
    serverResponse.messageType !== 'initialResponse'
  ) {
    servers[baseUrl].updating = false
    const e = new Error('Authrite version incompatible')
    e.code = 'ERR_INVALID_AUTHRITE_VERSION'
    throw e
  }

  // Validate server signature
  let signature, verified
  // Construct the message for verification
  const messageToVerify = clients[baseUrl].nonce + serverResponse.nonce

  // Determine which signing strategy to use
  if (signingStrategy === 'Babbage') {
    signature = Buffer.from(serverResponse.signature, 'hex').toString('base64')

    // Verify the signature created by the SDK
    verified = await BabbageSDK.verifySignature({
      data: Buffer.from(messageToVerify),
      signature,
      protocolID: [2, 'authrite message signature'],
      keyID: `${clients[baseUrl].nonce} ${serverResponse.nonce}`,
      counterparty: serverResponse.identityKey
    })
  } else {
    // 1. Obtain the client's signing public key
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: clientPrivateKey,
      recipientPublicKey: serverResponse.identityKey,
      invoiceNumber: `2-authrite message signature-${clients[baseUrl].nonce} ${serverResponse.nonce}`,
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
    servers[baseUrl].updating = false
    const e = new Error('Unable to verify server signature!')
    e.code = 'ERR_INVALID_SIGNATURE'
    throw e
  }

  // Save the server's identity key and initial nonce
  // This allows future requests to be linked to the same session
  servers[baseUrl].identityPublicKey = serverResponse.identityKey
  servers[baseUrl].nonce = serverResponse.nonce

  // Check certificates were requested, and that the client is using Babbage as the signing strategy
  if (serverResponse.requestedCertificates && serverResponse.requestedCertificates.certifiers && serverResponse.requestedCertificates.certifiers.length !== 0 && this.signingStrategy === 'Babbage') {
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
        certificates.every(existingCert => {
          if (existingCert.signature === cert.signature) {
            // skip the duplicate cert found!
            duplicate = true
            return false
          }
          return true
        })
        if (!duplicate) {
          certificates.push(cert)
          duplicate = false
        }
      })
    }
  }
  servers[baseUrl].requestedCertificates = serverResponse.requestedCertificates
  servers[baseUrl].updating = false
}
module.exports = verifyServerInitialResponse
