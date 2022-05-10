/**
 * Figure out the type of data and parse it correctly
 * TODO: Add support for more types of data
 * @param {object} fetchConfig Config object passed to the fetch API
 * @param {string} url The server baseUrl + the route path
 */
const getDataToSign = (fetchConfig, url) => {
  if (fetchConfig.body) {
    if (fetchConfig.headers['Content-Type'] === 'application/json') {
      return JSON.stringify(JSON.parse(fetchConfig.body))
    } else if (fetchConfig.headers['Content-Type'] === 'text/plain') {
      // TODO
    } else if (fetchConfig.headers['Content-Type'] === 'text/html') {
      // TODO
    }
  }
  return url
}
module.exports = { getDataToSign }
