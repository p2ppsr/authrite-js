/* eslint-env jest */
const bsv = require('babbage-bsv')
const boomerang = require('boomerang-http')
const sendover = require('sendover')
const { Authrite } = require('../authrite')
const crypto = require('crypto')
const fetch = require('node-fetch')

jest.mock('boomerang-http')
jest.mock('node-fetch')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

describe('authrite', () => {
  beforeEach(() => {
    boomerang.mockImplementation(async (method, url, data, headers) => {
      const serverNonce = crypto.randomBytes(32).toString('base64')
      const message = data.nonce + serverNonce
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: data.identityKey,
        invoiceNumber: '2-authrite message signature-' + data.nonce + ' ' + serverNonce,
        returnType: 'wif'
      })
      const signature = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(Buffer.from(message)), bsv.PrivateKey.fromWIF(derivedPrivateKey))
      return {
        authrite: '0.1',
        messageType: 'initialResponse',
        identityKey: bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
        nonce: serverNonce,
        certificates: [],
        requestedCertificates: [],
        signature: signature.toString()
      }
    })
    fetch.mockImplementation(async (url, fetchConfig) => {
      const serverNonce = crypto.randomBytes(32).toString('base64')
      const message = {
        message: 'hello Authrite'
      }
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: fetchConfig.headers['X-Authrite-Identity-Key'],
        invoiceNumber: '2-authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'wif'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(message))),
        bsv.PrivateKey.fromWIF(derivedPrivateKey)
      )
      const headers = {
        'x-authrite': '0.1',
        'x-authrite-identity-key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
        'x-authrite-nonce': serverNonce,
        'x-authrite-yournonce': fetchConfig.headers['X-Authrite-Nonce'],
        'x-authrite-certificates': [],
        'x-authrite-signature': responseSignature.toString()
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
    })
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('Throws an error if the client private key is not a 256-bit (32 byte) hex value', async () => {
    expect(() => new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY + TEST_CLIENT_PRIVATE_KEY
    })).toThrow('Please provide a valid client private key!')
  }, 100000)
  it('populates a new authrite instance', () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    const expectedClient = {
      initialRequestPath: '/authrite/initialRequest',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      clientPublicKey: bsv.PrivateKey
        .fromHex(TEST_CLIENT_PRIVATE_KEY)
        .publicKey.toString(),
      signingStrategy: 'ClientPrivateKey',
      clients: {},
      servers: {}
    }
    expect(JSON.parse(JSON.stringify(authrite))).toEqual(
      expectedClient
    )
  })
  it('performs an initial server request', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    await authrite.request('https://server.com/apiRoute')
    expect(boomerang).toHaveBeenCalledWith(
      'POST',
      'https://server.com/authrite/initialRequest',
      {
        authrite: '0.1',
        messageType: 'initialRequest',
        identityKey: authrite.clientPublicKey,
        nonce: authrite.clients['https://server.com'].nonce,
        requestedCertificates: []
      }
    )
    const expectedClient = {
      initialRequestPath: '/authrite/initialRequest',
      clientPublicKey: '0408c91c1361546c46672cd2c4c7fba7799e785edef509802fd966ad4cce13ad2e038590f44656cf1ae962e21b72039c8579b637c13401317592746db05e443dcd',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      signingStrategy: 'ClientPrivateKey',
      clients: {
        'https://server.com': {
          certificates: [],
          nonce: expect.any(String)
        }
      },
      servers: {
        'https://server.com': {
          baseUrl: 'https://server.com',
          certificates: [],
          identityPublicKey: '04b51d497f8c67c1416cfe1a58daa5a576a63eb0b64608922d5c4f98b6a1d9b103f9c42cd08b1376ec1932be02c7debdc5314fa563d383d61f8110a5df910bc719',
          nonce: expect.any(String),
          requestedCertificates: []
        }
      }
    }
    expect(JSON.parse(JSON.stringify(authrite))).toEqual(
      expectedClient
    )
  })
  it('sends a valid signed request with empty body to the server', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })

    // Save the client's headers so we can verify the fetch request for testing
    let clientIdentityKey = ''
    let clientNonce = ''
    let clientSig = ''
    let responseMessage = ''
    fetch.mockImplementation(async (url, fetchConfig) => {
      // Generate a new server nonce to use for signing the response
      const serverNonce = crypto.randomBytes(32).toString('base64')
      // Temporarily save client request info for testing purposes
      clientIdentityKey = fetchConfig.headers['X-Authrite-Identity-Key']
      clientNonce = fetchConfig.headers['X-Authrite-Nonce']
      clientSig = fetchConfig.headers['X-Authrite-Signature']
      responseMessage = {
        message: 'hello Authrite'
      }
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: fetchConfig.headers['X-Authrite-Identity-Key'],
        invoiceNumber: '2-authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'wif'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
        bsv.PrivateKey.fromWIF(derivedPrivateKey))
      const headers = {
        'x-authrite': '0.1',
        'x-authrite-identity-key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
        'x-authrite-nonce': serverNonce,
        'x-authrite-yournonce': fetchConfig.headers['X-Authrite-Nonce'],
        'x-authrite-certificates': [],
        'x-authrite-signature': responseSignature.toString()
      }
      return {
        arrayBuffer: () => Buffer.from(JSON.stringify(responseMessage), 'utf8'),
        body: responseMessage,
        headers: {
          ...headers,
          get: jest.fn(x => headers[x.toLowerCase()])
        }
      }
    })
    // Make a request with no fetchConfig object
    const response = await authrite.request('https://server.com/apiRoute')
    expect(fetch).toHaveBeenCalledWith(
      'https://server.com/apiRoute',
      {
        method: 'GET',
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': clientIdentityKey,
          'X-Authrite-Nonce': clientNonce,
          'X-Authrite-YourNonce': expect.any(String),
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': clientSig
        }
      }
    )
    // Verify that the response signature was verified by the client
    expect(JSON.parse(response.body.toString('utf8'))).toEqual(responseMessage)
  })
  it('sends a valid signed request with a payload to the server', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest'
    })

    // Save the client's headers so we can verify the fetch request for testing
    let clientIdentityKey = ''
    let clientNonce = ''
    let clientSig = ''
    let responseMessage = ''
    fetch.mockImplementation(async (url, fetchConfig) => {
      clientIdentityKey = fetchConfig.headers['X-Authrite-Identity-Key']
      clientNonce = fetchConfig.headers['X-Authrite-Nonce']
      const serverNonce = crypto.randomBytes(32).toString('base64')
      clientSig = fetchConfig.headers['X-Authrite-Signature']
      responseMessage = {
        message: 'hello Authrite'
      }
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: fetchConfig.headers['X-Authrite-Identity-Key'],
        invoiceNumber: '2-authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'wif'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
        bsv.PrivateKey.fromWIF(derivedPrivateKey))
      const headers = {
        'x-authrite': '0.1',
        'x-authrite-identity-key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
        'x-authrite-nonce': serverNonce,
        'x-authrite-yournonce': fetchConfig.headers['X-Authrite-Nonce'],
        'x-authrite-certificates': [],
        'x-authrite-signature': responseSignature.toString()
      }
      return {
        arrayBuffer: () => Buffer.from(JSON.stringify(responseMessage), 'utf8'),
        body: responseMessage,
        json: async () => responseMessage,
        headers: {
          ...headers,
          get: jest.fn(x => headers[x.toLowerCase()])
        }
      }
    })
    // Include fetchConfig with a payload in the request
    const response = await authrite.request('https://server.com/apiRoute', {
      body: {
        message: 'Hello Authrite server!',
        date: new Date().getHours()
      },
      method: 'POST'
    })
    expect(fetch).toHaveBeenCalledWith(
      'https://server.com/apiRoute',
      {
        body: JSON.stringify({
          message: 'Hello Authrite server!',
          date: new Date().getHours()
        }),
        method: 'POST',
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': clientIdentityKey,
          'X-Authrite-Nonce': clientNonce,
          'X-Authrite-YourNonce': expect.any(String),
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': clientSig,
          'Content-Type': 'application/json'
        }
      }
    )
    // Verify that the response signature was verified by the client
    expect(JSON.parse(response.body.toString('utf8'))).toEqual(responseMessage)
  })
})
