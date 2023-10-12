/* eslint-env jest */
const bsv = require('babbage-bsv')
const boomerang = require('boomerang-http')
const { Authrite } = require('../src/authrite')
const fetch = require('node-fetch')
const cryptononce = require('cryptononce')

// Test Util Functions
const { getResponseAuthHeaders } = require('authrite-utils')

jest.mock('boomerang-http')
jest.mock('node-fetch')
jest.mock('socket.io-client')

const AUTHRITE_VERSION = '0.2'
const BASE_URL = 'https://server.com'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'
const SERVER_NONCE = 'Ea2SOkMQiMbdCv4uinGmVIqAT+mRkq9VSIX+LG6cKso='

describe('authrite HTTP functionality', () => {
  // Holds the last state of any fetch requests (cleared after each)
  let testFetchConfig
  let testFetchResponse

  beforeEach(() => {
    testFetchConfig = {}

    // Mock the Authrite express initial response
    boomerang.mockImplementation(async (method, url, data, headers) => {
      const messageToSign = data.nonce + SERVER_NONCE
      return await getResponseAuthHeaders({
        authrite: AUTHRITE_VERSION,
        messageType: 'initialResponse',
        serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
        clientPublicKey: data.identityKey,
        clientNonce: data.nonce,
        serverNonce: SERVER_NONCE,
        messageToSign,
        certificates: []
      })
    })

    // Mock the Authrite express fetch response
    fetch.mockImplementation(async (url, fetchConfig) => {
      testFetchConfig = fetchConfig
      const responseNonce = cryptononce.createNonce(TEST_SERVER_PRIVATE_KEY)
      const messageToSign = 'https://server.com/apiRoute'
      testFetchResponse = await getResponseAuthHeaders({
        authrite: AUTHRITE_VERSION,
        serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
        clientPublicKey: fetchConfig.headers['x-authrite-identity-key'],
        clientNonce: fetchConfig.headers['x-authrite-initialnonce'],
        serverNonce: responseNonce,
        messageToSign: Buffer.from(JSON.stringify(messageToSign), 'utf8'),
        certificates: []
      })
      return {
        arrayBuffer: () => Buffer.from(JSON.stringify(messageToSign), 'utf8'),
        body: messageToSign,
        json: async () => messageToSign,
        status: 200,
        headers: {
          ...testFetchResponse,
          forEach: jest.fn(),
          get: jest.fn(x => testFetchResponse[x.toLowerCase()])
        }
      }
    })
  })
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('Throws an error if the client private key is not a 256-bit (32 byte) hex value', async () => {
    const invalidPrivateKey = TEST_CLIENT_PRIVATE_KEY + TEST_CLIENT_PRIVATE_KEY
    expect(() => new Authrite({
      clientPrivateKey: invalidPrivateKey
    })).toThrow('Please provide a valid client private key!')
  }, 100000)

  it('Constructs a new authrite instance', () => {
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
      servers: {},
      certificates: []
    }
    expect(JSON.parse(JSON.stringify(authrite))).toEqual(
      expectedClient
    )
  })

  it('Adds a new unique certificate to the Authrite instance', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    // Adding a signature with a new signature adds it to certificates with additional "keyrings: {}" prop.
    // The only certificate property that matters is "signature"
    const dummyTestCert = { signature: '<signature_as_hex_string_1>' }
    expect(authrite.certificates.length).toEqual(0)

    authrite.addCertificate(dummyTestCert)
    expect(authrite.certificates.length).toEqual(1)
    expect(authrite.certificates[0].keyrings).toEqual({})

    // Adding a signature with the same signature is ignored.
    authrite.addCertificate(dummyTestCert)
    expect(authrite.certificates.length).toEqual(1)
  })

  it('performs an initial server request', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    await authrite.request(`${BASE_URL}/apiRoute`)
    expect(boomerang).toHaveBeenCalledWith(
      'POST',
      `${BASE_URL}/authrite/initialRequest`,
      {
        authrite: AUTHRITE_VERSION,
        messageType: 'initialRequest',
        identityKey: authrite.clientPublicKey,
        nonce: authrite.clients[BASE_URL].nonce,
        requestedCertificates: []
      }
    )
  })

  it('sends a valid signed request with empty body to the server', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })

    // Make a simple GET request
    const requestPath = `${BASE_URL}/apiRoute`
    const response = await authrite.request(requestPath)

    // Validate a fetch call was made
    expect(fetch).toHaveBeenCalledWith(
      requestPath,
      {
        method: 'GET',
        headers: {
          'x-authrite': AUTHRITE_VERSION,
          'x-authrite-identity-key': new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
          'x-authrite-nonce': testFetchConfig.headers['x-authrite-nonce'],
          'x-authrite-initialnonce': authrite.clients[BASE_URL].nonce,
          'x-authrite-yournonce': authrite.servers[BASE_URL].nonce,
          'x-authrite-certificates': JSON.stringify([]),
          'x-authrite-signature': testFetchConfig.headers['x-authrite-signature']
        }
      }
    )

    // Verify that the response signature was verified by the client
    // expect(JSON.parse(response.body.toString('utf8'))).toEqual(testFetchResponse.body)
  })

  it('sends a valid signed request with a payload to the server', async () => {
    const authrite = new Authrite({
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest'
    })

    // Make a POST request with an object payload
    const requestPath = `${BASE_URL}/apiRoute`
    const payload = {
      message: 'Hello Authrite server!',
      date: new Date().getHours()
    }

    // Include fetchConfig with a payload in the request
    const response = await authrite.request(requestPath, {
      body: payload,
      method: 'POST'
    })

    // Validate the fetch call made
    expect(fetch).toHaveBeenCalledWith(
      requestPath,
      {
        body: JSON.stringify(payload),
        method: 'POST',
        headers: {
          'x-authrite': AUTHRITE_VERSION,
          'x-authrite-identity-key': new bsv.PrivateKey(TEST_CLIENT_PRIVATE_KEY).publicKey.toString(),
          'x-authrite-nonce': testFetchConfig.headers['x-authrite-nonce'],
          'x-authrite-initialnonce': authrite.clients[BASE_URL].nonce,
          'x-authrite-yournonce': authrite.servers[BASE_URL].nonce,
          'x-authrite-certificates': JSON.stringify([]),
          'x-authrite-signature': testFetchConfig.headers['x-authrite-signature'],
          'Content-Type': 'application/json'
        }
      }
    )

    // Verify that the response signature was verified by the client
    // expect(JSON.parse(response.body.toString('utf8'))).toEqual(testFetchResponse.body)
  })
})

// describe('authrite socket functionality', () => {
//   beforeEach(() => {
//   })
//   afterEach(() => {
//     jest.clearAllMocks()
//   })
//   it.todo('constructs a new Authrite instance with a socket connection available')
// })
