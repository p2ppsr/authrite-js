# authrite-js

JavaScript client for Authrite

The code is available [on GitHub](https://github.com/p2ppsr/authrite-js) and the package is published [on NPM](https://www.npmjs.com/package/authrite-js).

## Overview

[Authrite](https://projectbabbage.com/authrite) is a system for mutual authentication over a communications channel where both parties come to know the identity of the counterparty.
**authrite-js** provides an API for making authenticated HTTP requests from a client to a server that uses the authrite-express middleware.

During setup, the client asks for some basic information from the server and provides their identity key. The server sends back a reply, proving custody over the identity key they send back. Then, every message sent between the two parties is signed and verified, enabling everyone to have confidence in message integrity. Messages are not encrypted by Authrite, but encryption is provided by HTTPS.

## Installation

    npm i authrite-js

## Example Usage

This example demonstrates sending a simple request sent with **authrite-js**

```js
const { Authrite } = require('authrite-js')

// Authrite required parameters
const EXAMPLE_CLIENT_PRIVATE_KEY = 
'0d7889a0e56684ba795e9b1e28eb906df43454f8172ff3f6807b8cf9464994df'
const EXAMPLE_SERVER_BASEURL = 'http://localhost:5000'

const init = async () => {
    // Create a new instance of the Authrite class
    // Provide the server baseUrl, and your private identity key
    const authrite = new Authrite({
        baseUrl: TEST_SERVER_BASEURL,
        clientPrivateKey: TEST_CLIENT_PRIVATE_KEY
    })
    // Construct a payload to send as the body of your request
    const body = {
        user: 'Bob',
        message: 'message from client'
    }
    // Create a new request to the server
    const response = await authrite.request('/sendSomeData', {
        body,
        method: 'POST',
        headers: {
        'Content-Type': 'application/json'
        }
    })
    // Retrieve the response from the server
    const responseData = JSON.parse(Buffer.from(response.body).toString('utf8'))
}

init()
```

## API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

#### Table of Contents

*   [Authrite](#authrite)
    *   [Parameters](#parameters)
    *   [request](#request)
        *   [Parameters](#parameters-1)

### Authrite

Client-side API for establishing authenticated server communication

#### Parameters

*   `authrite` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are given in an object.

    *   `authrite.baseUrl` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The server baseUrl we want to talk to
    *   `authrite.clientPrivateKey` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The client's private key used for derivations
    *   `authrite.initialRequestPath` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Initial request path for establishing a connection (optional, default `'/authrite/initialRequest'`)
    *   `authrite.initialRequestMethod` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Initial request method (optional, default `'POST'`)

#### request

##### Parameters

*   `routePath` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The path on the server to request
*   `fetchConfig` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** Config object passed to the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API).
    The current version of Authrite only supports JSON structures for the fetch body. However, you can include a [Buffer](https://nodejs.org/api/buffer.html) as part of the json object. (optional, default `{}`)

Returns **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The response object. Fields are 'headers' and 'body' (containing messageToVerify)

## License

The license for the code in this repository is the Open BSV License.
