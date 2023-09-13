const { getPaymentAddress } = require('sendover')
const BabbageSDK = require('@babbage/sdk')
const bsv = require('babbage-bsv')

const verifyServerSignature = async ({ authriteVersion, baseUrl, signingStrategy, clientPrivateKey, clients, servers, serverResponse, certificates }) => {
  // Check serverResponse for errors
  if (serverResponse.status === 'error') {
    servers[baseUrl].updating = false
    const e = new Error(`${serverResponse.code} --> ${serverResponse.description} Please check the Authrite baseURL and initial request path config`)
    e.code = 'ERR_INVALID_SERVER_REQUEST'
    throw e
  }

  if (
    serverResponse['x-authrite'] !== authriteVersion ||
        serverResponse['x-message-type'] !== 'initialResponse'
  ) {
    servers[baseUrl].updating = false
    const e = new Error('Authrite version incompatible')
    e.code = 'ERR_INVALID_AUTHRITE_VERSION'
    throw e
  }
  // Validate server signature
  let signature, verified
  // Construct the message for verification
  const messageToVerify = clients[baseUrl].nonce + serverResponse['x-authrite-nonce']
  if (signingStrategy === 'Babbage') {
    signature = Buffer.from(serverResponse['x-authrite-signature'], 'hex').toString('base64')
    // Verify the signature created by the SDK
    verified = await BabbageSDK.verifySignature({
      data: Buffer.from(messageToVerify),
      signature,
      protocolID: [2, 'authrite message signature'],
      keyID: `${clients[baseUrl].nonce} ${serverResponse['x-authrite-nonce']}`,
      counterparty: serverResponse['x-authrite-identity-key']
    })
  } else {
    // 1. Obtain the client's signing public key
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: clientPrivateKey,
      recipientPublicKey: serverResponse['x-authrite-identity-key'],
      invoiceNumber: `2-authrite message signature-${clients[baseUrl].nonce} ${serverResponse['x-authrite-nonce']}`,
      returnType: 'publicKey'
    })
    // 2. Verify the signature
    signature = bsv.crypto.Signature.fromString(serverResponse['x-authrite-signature'])
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
  servers[baseUrl].identityPublicKey = serverResponse['x-authrite-identity-key']
  servers[baseUrl].nonce = serverResponse['x-authrite-nonce']

  // Check certificates were requested, and that the client is using Babbage as the signing strategy
  if (serverResponse['x-authrite-certificates'].certifiers && serverResponse['x-authrite-certificates'].certifiers.length !== 0 && signingStrategy === 'Babbage') {
    // Find matching certificates
    let matchingCertificates = await BabbageSDK.getCertificates({
      certifiers: serverResponse['x-authrite-certificates'].certifiers,
      types: serverResponse['x-authrite-certificates'].types
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
  servers[baseUrl].requestedCertificates = serverResponse['x-authrite-certificates']
  servers[baseUrl].updating = false
}
module.exports = verifyServerSignature
