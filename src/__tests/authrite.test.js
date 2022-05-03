/* eslint-env jest */
const bsv = require('bsv')
const boomerang = require('boomerang-http')
const sendover = require('sendover')
const { Authrite } = require('../authrite')
const crypto = require('crypto')

jest.mock('boomerang-http')

const TEST_CLIENT_PRIVATE_KEY = '0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const TEST_SERVER_PRIVATE_KEY = '6dcc124be5f382be631d49ba12f61adbce33a5ac14f6ddee12de25272f943f8b'

describe('authrite', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })
  it('populates a new authrite instance', () => {
    const client = new Authrite({
      server: 'https://server.com',
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      initialRequestPath: '/authrite/initialRequest',
      initialRequestMethod: 'POST'
    })
    const expectedClient = {
      server: 'https://server.com',
      serverIdentityPublicKey: null,
      serverNonce: null,
      serverCertificates: [],
      serverRequestedCertificates: [],
      clientNonce: expect.any(String),
      clientPrivateKey: TEST_CLIENT_PRIVATE_KEY,
      clientPublicKey: '0408c91c1361546c46672cd2c4c7fba7799e785edef509802fd966ad4cce13ad2e038590f44656cf1ae962e21b72039c8579b637c13401317592746db05e443dcd',
      initialRequestPath: '/authrite/initialRequest',
      initalRequestMethod: 'POST'
    }
    expect(JSON.parse(JSON.stringify(client))).toEqual(
      expectedClient
    )
  })
  it('performs an initial server request', async () => {
    const client = new Authrite({
      server: 'https://server.com',
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
      console.log(message)
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
    console.log('Client Before: ', client)
    await client.request('POST', 'server_url',
      {
        data: 'somedata'
      },
      {}
    )
    console.log('Client After Request: ', client)
    expect(boomerang).toHaveBeenCalledWith(
      'POST',
      'https://server.com/authrite/initialRequest',
      {
        authrite: '0.1',
        messageType: 'initialRequest',
        identityKey: client.clientPublicKey,
        nonce: client.clientNonce,
        requestedCertificates: [] // TODO: provide requested certificates
      })
  })
})
