/* eslint-env jest */
const bsv = require('bsv')
const boomerang = require('boomerang-http')
const sendover = require('sendover')
const { Authrite } = require('../authrite')
const crypto = require('crypto')
const fetch = require('isomorphic-fetch')

jest.mock('boomerang-http')
jest.mock('isomorphic-fetch')

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
        invoiceNumber: 'authrite message signature-' + data.nonce + ' ' + serverNonce,
        returnType: 'hex'
      })
      const signature = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(Buffer.from(message)), bsv.PrivateKey.fromHex(derivedPrivateKey))
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
        invoiceNumber: 'authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'hex'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(message))),
        bsv.PrivateKey.fromHex(derivedPrivateKey)
      )
      return {
        body: message,
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
          'X-Authrite-Nonce': serverNonce,
          'X-Authrite-YourNonce': fetchConfig.headers['X-Authrite-Nonce'],
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': responseSignature.toString()
        }
      }
    })
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('populates a new authrite instance', () => {
    const authrite = new Authrite({
      serverUrl: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const expectedClient = {
      initalRequestMethod: 'POST',
      initialRequestPath: '/authrite/initialRequest',
      client: {
        nonce: expect.any(String),
        privateKey: TEST_CLIENT_PRIVATE_KEY,
        publicKey: '0408c91c1361546c46672cd2c4c7fba7799e785edef509802fd966ad4cce13ad2e038590f44656cf1ae962e21b72039c8579b637c13401317592746db05e443dcd',
        certificates: []
      },
      server: {
        baseUrl: 'https://server.com',
        certificates: [],
        identityPublicKey: null,
        nonce: null,
        requestedCertificates: []
      }
    }
    expect(JSON.parse(JSON.stringify(authrite))).toEqual(
      expectedClient
    )
  })
  it('performs an initial server request', async () => {
    const authrite = new Authrite({
      serverUrl: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    await authrite.request('/apiRoute')
    expect(boomerang).toHaveBeenCalledWith(
      'POST',
      'https://server.com/authrite/initialRequest',
      {
        authrite: '0.1',
        messageType: 'initialRequest',
        identityKey: authrite.client.publicKey,
        nonce: authrite.client.nonce,
        requestedCertificates: [] // TODO: provide requested certificates
      })
  })
  it('sends a valid signed request with empty body to the server', async () => {
    const authrite = new Authrite({
      serverUrl: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
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
        invoiceNumber: 'authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'hex'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
        bsv.PrivateKey.fromHex(derivedPrivateKey))
      return {
        body: responseMessage,
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
          'X-Authrite-Nonce': serverNonce,
          'X-Authrite-YourNonce': fetchConfig.headers['X-Authrite-Nonce'],
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': responseSignature.toString()
        }
      }
    })
    // Make a request with no fetchConfig object
    const response = await authrite.request('/apiRoute')
    expect(fetch).toHaveBeenCalledWith(
      'https://server.com/apiRoute',
      {
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
    expect(response.body).toEqual(responseMessage)
  })
  it('sends a valid signed request with a payload to the server', async () => {
    const authrite = new Authrite({
      serverUrl: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
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
        invoiceNumber: 'authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
        returnType: 'hex'
      })
      const responseSignature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
        bsv.PrivateKey.fromHex(derivedPrivateKey))
      return {
        body: responseMessage,
        headers: {
          'X-Authrite': '0.1',
          'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(TEST_SERVER_PRIVATE_KEY).publicKey.toString(),
          'X-Authrite-Nonce': serverNonce,
          'X-Authrite-YourNonce': fetchConfig.headers['X-Authrite-Nonce'],
          'X-Authrite-Certificates': [],
          'X-Authrite-Signature': responseSignature.toString()
        }
      }
    })
    // Include fetchConfig with a payload in the request
    const response = await authrite.request('/apiRoute', {
      payload: {
        message: 'Hello Authrite server!',
        date: new Date().getHours()
      }
    })
    expect(fetch).toHaveBeenCalledWith(
      'https://server.com/apiRoute',
      {
        payload: {
          message: 'Hello Authrite server!',
          date: new Date().getHours()
        },
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
    expect(response.body).toEqual(responseMessage)
  })
})
