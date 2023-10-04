/**
 * Construct BRC-31 compliant authentication headers to send to the server
 * Note: Currently assumes initial param validation has been done. TODO: Add it here as well
 * Note: Also doesn't currently support the initial request response here. TODO: add it here as well
 * @param {object} obj - all params given in an object
 * @param {string} obj.authriteVersion - the current version of Authrite being used
 * @param {string} obj.clientPublicKey - of the current client making the request
 * @param {string} obj.requestNonce - random nonce provided by the client
 * @param {string} obj.serverInitialNonce - initial session nonce provided by the server
 * @param {string} obj.requestSignature - message signature provided as a hex string
 * @param {Array}  obj.certificatesToInclude - authrite certificates provided to the server upon request
 * @returns {object} - valid auth headers
 */
const getRequestAuthHeaders = async ({
  authriteVersion,
  clientPublicKey,
  requestNonce,
  clientInitialNonce,
  serverInitialNonce,
  requestSignature,
  certificatesToInclude
}) => {
  return {
    'x-authrite': authriteVersion,
    'x-authrite-identity-key': clientPublicKey,
    'x-authrite-nonce': requestNonce,
    'x-authrite-initialnonce': clientInitialNonce,
    'x-authrite-yournonce': serverInitialNonce,
    'x-authrite-signature': requestSignature,
    'x-authrite-certificates': certificatesToInclude
  }
}
module.exports = getRequestAuthHeaders
