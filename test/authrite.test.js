/* eslint-env jest */
const bsv = require('babbage-bsv')
const boomerang = require('boomerang-http')
const { Authrite } = require('../src/authrite')
const fetch = require('node-fetch')

// Test Util Functions
const { getServerInitialResponse, getMockAuthriteFetchResponse, getExpectedFetchRequestConfig } = require('./utils/mockAuthriteExpress')

jest.mock('boomerang-http')
jest.mock('node-fetch')
jest.mock('socket.io-client')

const AUTHRITE_VERSION = '0.2'
const BASE_URL = 'https://server.com'
const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

describe('authrite HTTP functionality', () => {
  // Holds the last state of any fetch requests (cleared after each)
  let testFetchConfig
  let testFetchResponse

  beforeEach(() => {
    testFetchConfig = {}

    // Mock the Authrite express initial response
    boomerang.mockImplementation(async (method, url, data, headers) => {
      return await getServerInitialResponse({
        data,
        serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
        authriteVersion: AUTHRITE_VERSION
      })
    })

    // Mock the Authrite express fetch response
    fetch.mockImplementation(async (url, fetchConfig) => {
      testFetchConfig = fetchConfig
      testFetchResponse = await getMockAuthriteFetchResponse({
        fetchConfig,
        message: url,
        serverPrivateKey: TEST_SERVER_PRIVATE_KEY,
        authriteVersion: AUTHRITE_VERSION
      })
      return testFetchResponse
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
      getExpectedFetchRequestConfig({
        authrite,
        testFetchConfig,
        baseUrl: BASE_URL,
        authriteVersion: AUTHRITE_VERSION,
        clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
      })
    )

    // Verify that the response signature was verified by the client
    expect(JSON.parse(response.body.toString('utf8'))).toEqual(testFetchResponse.body)
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
          ...getExpectedFetchRequestConfig({
            authrite,
            testFetchConfig,
            baseUrl: BASE_URL,
            authriteVersion: AUTHRITE_VERSION,
            clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
          }).headers,
          'Content-Type': 'application/json'
        }
      }
    )

    // Verify that the response signature was verified by the client
    expect(JSON.parse(response.body.toString('utf8'))).toEqual(testFetchResponse.body)
  })
})

describe('authrite socket functionality', () => {
  beforeEach(() => {
  })
  afterEach(() => {
    jest.clearAllMocks()
  })
  it.todo('constructs a new Authrite instance with a socket connection available')
})
