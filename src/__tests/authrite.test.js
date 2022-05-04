/* eslint-env jest */
const bsv = require('bsv')
const boomerang = require('boomerang-http')
const sendover = require('sendover')
const { Authrite } = require('../authrite')
const crypto = require('crypto')
const fetchMock = require('fetch-mock')

jest.mock('boomerang-http')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

describe('authrite', () => {
  beforeEach(() => {
    fetchMock.mock('http://server.com/apiRoute', 200)
  })
  afterEach(() => {
    jest.clearAllMocks()
    fetchMock.reset()
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
        publicKey: '0408c91c1361546c46672cd2c4c7fba7799e785edef509802fd966ad4cce13ad2e038590f44656cf1ae962e21b72039c8579b637c13401317592746db05e443dcd'
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
    boomerang.mockImplementation(async (method, url, data, headers) => {
      const serverNonce = crypto.randomBytes(32).toString('base64')
      const message = data.nonce + serverNonce
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: data.identityKey,
        invoiceNumber: 'authrite message signature-' + data.nonce + ' ' + serverNonce,
        returnType: 'hex'
      })
    //   console.log(message)
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
    // console.log('Client Before: ', authrite)
    await authrite.request('/apiRoute')
    console.log('Client After Request: ', authrite)
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
  it('sends a valid signed request and payload to the server', async () => {
    const authrite = new Authrite({
      serverUrl: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    boomerang.mockImplementation(async (method, routePath, data, headers) => {
      const serverNonce = crypto.randomBytes(32).toString('base64')
      const message = data.nonce + serverNonce
      const derivedPrivateKey = sendover.getPaymentPrivateKey({
        recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
        senderPublicKey: data.identityKey,
        invoiceNumber: 'authrite message signature-' + data.nonce + ' ' + serverNonce,
        returnType: 'hex'
      })
      const payload = data.payload
      console.log('Payload: ', payload)
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
    console.log('Client Before: ', authrite)
    await authrite.request('POST', '/routepath',
      {
        data: 'Hello Authrite!'
      },
      {}
    )
    console.log('Client After Request: ', authrite)
    expect(boomerang).toHaveBeenCalledWith(
      'POST',
      'https://server.com/authrite/initialRequest',
      {
        authrite: '0.1',
        messageType: 'initialRequest',
        identityKey: authrite.client.publicKey,
        nonce: authrite.client.nonce,
        requestedCertificates: [] // TODO: provide requested certificates
      }
    )
    expect(boomerang).toHaveBeenLastCalledWith(
      'POST',
      'https://server.com/routepath',
      {
        authrite: '0.1',
        identityKey: authrite.client.publicKey,
        nonce: authrite.client.nonce,
        certificates: authrite.client.certificates,
        payload: {
          data: 'Hello Authrite!'
        }
      }
    )
  })
})
