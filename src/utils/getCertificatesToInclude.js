const BabbageSDK = require('@babbage/sdk')

/**
 * Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested
 * @param {object} obj - all params provided in an object
 * @param {string} obj.signingStrategy - specifies which signing strategy should be used
 * @param {object} obj.servers - the servers the current Authrite instance is interacting with
 * @param {Array}  obj.certificates - the current available certificates
 * @returns
 */
const getCertificatesToInclude = async ({
  signingStrategy,
  baseUrl,
  servers,
  certificates
}) => {
  // Provide a list of certificates with acceptable type and certifier values for the request, based on what the server requested.
  const requestedCerts = servers[baseUrl].requestedCertificates
  const certificatesToInclude = certificates.filter(cert =>
    requestedCerts.certifiers.includes(cert.certifier) &&
      Object.keys(requestedCerts.types).includes(cert.type)
  )

  await Promise.all(certificatesToInclude.map(async cert => {
    // Check if a keyring exists for this server/verifier.
    const verifierKeyring = cert.keyrings[servers[baseUrl].identityPublicKey]
    const requestedFields = servers[baseUrl].requestedCertificates.types[cert.type]

    // IF an existing keyring has been found, compare the list of fields from the keyring with the list of fields this server is requesting for this certificate type.
    // TODO: Consider refactoring array comparison.
    if (
      !verifierKeyring ||
        JSON.stringify(Object.keys(verifierKeyring)) !==
        JSON.stringify(requestedFields)
    ) {
      // If there are differences, or no keyring, SDK proveCertificate function generates a new keyring for this verifier containing only the verifier’s requested fields.
      // Ensure Babbage signing strategy is used
      if (signingStrategy !== 'Babbage') {
        const e = new Error('No valid keyring, or method for obtaining keyring, for this certificate and verifier!')
        e.code = 'ERR_NO_CERT_PROOF_STRATEGY'
        throw e
      }
      const { keyring } = await BabbageSDK.proveCertificate({
        certificate: {
          fields: cert.fields,
          serialNumber: cert.serialNumber,
          validationKey: cert.validationKey,
          certifier: cert.certifier,
          subject: cert.subject,
          type: cert.type,
          revocationOutpoint: cert.revocationOutpoint,
          signature: cert.signature
        },
        fieldsToReveal: requestedFields,
        verifierPublicIdentityKey: servers[baseUrl].identityPublicKey
      })
      // Save the keyring for this verifier
      cert.keyrings[servers[baseUrl].identityPublicKey] = keyring
    }
    cert.keyring = cert.keyrings[servers[baseUrl].identityPublicKey]
  }))

  // return certificates with all extra removed
  return certificatesToInclude.map(cert => ({
    fields: cert.fields,
    serialNumber: cert.serialNumber,
    validationKey: cert.validationKey,
    certifier: cert.certifier,
    subject: cert.subject,
    type: cert.type,
    revocationOutpoint: cert.revocationOutpoint,
    signature: cert.signature,
    keyring: cert.keyring
  }))
}
module.exports = getCertificatesToInclude
