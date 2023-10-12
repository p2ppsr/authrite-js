/* eslint-env jest */
const bsv = require('babbage-bsv')
const { getPaymentPrivateKey } = require('sendover')
const cryptononce = require('cryptononce')
const crypto = require('crypto')

const getExpectedFetchRequestConfig = ({ authrite, testFetchConfig, baseUrl, authriteVersion, clientPrivateKey }) => {
  return {
    method: 'GET',
    headers: {
      'x-authrite': authriteVersion,
      'x-authrite-identity-key': new bsv.PrivateKey(clientPrivateKey).publicKey.toString(),
      'x-authrite-nonce': testFetchConfig.headers['x-authrite-nonce'],
      'x-authrite-initialnonce': authrite.clients[baseUrl].nonce,
      'x-authrite-yournonce': authrite.servers[baseUrl].nonce,
      'x-authrite-certificates': JSON.stringify([]),
      'x-authrite-signature': testFetchConfig.headers['x-authrite-signature']
    }
  }
}

/**
 * Mock Authrite server initial response
 * @param {object} obj - all params given in an object
 * @param {object} obj.data - request data
 * @param {string} obj.serverPrivateKey - mock server private key
 * @param {string} obj.authriteVersion - current authrite version
 * @returns
 */
const getServerInitialResponse = async ({ data, serverPrivateKey, authriteVersion }) => {
  const serverNonce = cryptononce.createNonce(serverPrivateKey)
  const messageToSign = data.nonce + serverNonce

  // Derive the signing private key
  const derivedPrivateKey = getPaymentPrivateKey({
    recipientPrivateKey: serverPrivateKey,
    senderPublicKey: data.identityKey,
    invoiceNumber: `2-authrite message signature-${data.nonce} ${serverNonce}`,
    returnType: 'hex'
  })

  // Sign the message
  const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(messageToSign)),
    bsv.PrivateKey.fromBuffer(Buffer.from(derivedPrivateKey, 'hex'))
  )

  return {
    authrite: authriteVersion,
    messageType: 'initialResponse',
    identityKey: bsv.PrivateKey.fromHex(serverPrivateKey).publicKey.toString(),
    nonce: serverNonce,
    certificates: [],
    requestedCertificates: [],
    signature: responseSignature.toString()
  }
}

/**
 * Mock a standard Authrite express response
 * Note: Consider using actual server-side helper functions if available...
 * @param {object} obj - all params given in an object
 * @param {object} obj.fetchConfig - request data
 * @param {string} obj.serverPrivateKey - mock server private key
 * @param {string} obj.authriteVersion - current authrite version
 * @returns
 */
const getMockAuthriteFetchResponse = async ({
  fetchConfig,
  message,
  serverPrivateKey,
  authriteVersion
}) => {
  const serverNonce = crypto.randomBytes(32).toString('base64')
  const derivedPrivateKey = getPaymentPrivateKey({
    recipientPrivateKey: serverPrivateKey,
    senderPublicKey: fetchConfig.headers['x-authrite-identity-key'],
    invoiceNumber: `2-authrite message signature-${fetchConfig.headers['x-authrite-initialnonce']} ${serverNonce}`,
    returnType: 'hex'
  })
  const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(message))),
    bsv.PrivateKey.fromBuffer(Buffer.from(derivedPrivateKey, 'hex'))
  )
  const headers = {
    'x-authrite': authriteVersion,
    'x-authrite-identity-key': new bsv.PrivateKey(serverPrivateKey).publicKey.toString('hex'),
    'x-authrite-nonce': serverNonce,
    'x-authrite-initialnonce': fetchConfig.headers['x-authrite-initialnonce'],
    'x-authrite-yournonce': fetchConfig.headers['x-authrite-nonce'],
    'x-authrite-certificates': [],
    'x-authrite-signature': responseSignature.toString(),
    forEach: jest.fn()
  }
  return {
    arrayBuffer: () => Buffer.from(JSON.stringify(message), 'utf8'),
    body: message,
    json: async () => message,
    status: 200,
    headers: {
      ...headers,
      get: jest.fn(x => headers[x.toLowerCase()])
    }
  }
}
module.exports = { getServerInitialResponse, getMockAuthriteFetchResponse, getExpectedFetchRequestConfig }
