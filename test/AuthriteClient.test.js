/* eslint-env jest */
const { AuthriteClient } = require('../src/AuthriteClient')
const sdk = require('@babbage/sdk-ts')

jest.mock('@babbage/sdk-ts')

describe('AuthriteClient', () => {
  beforeEach(() => {
  })
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('clients share Authrite', async () => {
    const client1 = new AuthriteClient('foo1.com')
    const client2 = new AuthriteClient('foo2.com')

    // expect(client1.authrite).toBe(AuthriteClient.Authrite)
    // expect(client2.authrite).toBe(AuthriteClient.Authrite)
    expect(client1.authrite === client2.authrite).toBe(true)
    expect(client1.serverURL).toBe('foo1.com')
    expect(client2.serverURL).toBe('foo2.com')
  })

  it('createSignedRequest success', async () => {
    const serverURL = 'foo1.com'
    const client = new AuthriteClient(serverURL)
    const result = { status: 'success' }

    client.authrite.request = jest.fn()
    client.authrite.request.mockReturnValue({ body: JSON.stringify(result) })

    const path = '/route1'
    const body = { a: 42, b: 'foobar' }
    const fetchConfig = {
      body,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }

    expect(await client.createSignedRequest(path, body)).toEqual(result)

    const calls = client.authrite.request.mock.calls
    expect(calls.length).toBe(1)
    expect(calls[0].length).toBe(2)
    expect(calls[0][0]).toBe(`${serverURL}${path}`)
    expect(calls[0][1]).toEqual(fetchConfig)
  })

  it('createSignedRequest error', async () => {
    const serverURL = 'foo1.com'
    const client = new AuthriteClient(serverURL)
    const result = { status: 'error', description: 'bad stuff happened', secret: 'included in error' }

    client.authrite.request.mockReturnValue({ body: JSON.stringify(result) })

    const path = '/route2'
    const body = { a: 42, b: 'foobar' }

    try {
      await client.createSignedRequest(path, body)
      expect(true).toBe(false)
    } catch (e) {
      expect(e.secret).toBe(result.secret)
      expect(e.message).toBe(result.description)
      expect(e.stack.startsWith(`Error: ${result.description}`)).toBe(true)
    }
  })

  it('createCertificate', async () => {
    const client = new AuthriteClient('foo1.com')

    const args = {
      certificateType: 1,
      fieldObject: 2,
      certifierUrl: 3,
      certifierPublicKey: 4
    }
    const cert = { foo: 'bar' }
    sdk.createCertificate.mockReturnValue(cert)
    client.authrite.addCertificate = jest.fn()
    client.authrite.addCertificate.mockReturnValue(0)

    expect(await client.createCertificate(args)).toEqual(cert)

    expect(sdk.createCertificate.mock.calls[0][0]).toEqual(args)
    expect(client.authrite.addCertificate.mock.calls[0][0]).toEqual(cert)
  })
})
