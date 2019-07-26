// ----------------------------------------------------------------------------
// CLIENT REGISTRATION FLOW
// https://simonmassey.bitbucket.io/thinbus/register.png
// Note as per RFC 2945 the user ID (usually their email) is concatenated to
// their password when generating the verifier. This means that if a user
// changes either their email address or their password you need to generate
// a new verifier and replace the old one in the database.
//                ┌──────────────┐                       ┌──────────────┐
//                │   Browser    │                       │  Web Server  │
//                └──────────────┘                       └──────┬───────┘
//                        │
//                                                              │
//     .─.              ┌─┴─┐        GET /index.html          ┌───┐
//    (   )             │   │<────────────────────────────────│   │
//     `┬'              │   │                                 └───┘
//  ────┼────           │   │                                   │
//      │  user,passwd  │   │
//     ┌┴┐ ────────────>|   ├──┐                                │
//     │ │              │   │  │         generateSalt()
//     │ │              │   │  │ generateVerifier(user, passwd) │
//   ──┘ └──            │   │<─┘
//                      │   │                                   │
//                      │   │
//                      │   │                                   │
//                      │   │   POST {user,salt,verifier}     ┌───┐
//                      │   ├────────────────────────────────>│   │
//                      │   │                                 └───┘
//                      └───┘                                   │
//                        │
// ----------------------------------------------------------------------------
// LOGIN FLOW
//
//                  ┌──────────────┐                       ┌──────────────┐
//                  │   Browser    │                       │  Web Server  │
//                  └──────────────┘                       └──────────────┘
//                          │                                     │
//      .─.               ┌───┐         GET /index.html         ┌───┐
//     (   ) user,passwd  │   │<────────────────────────────────│   │
//      `┬' ─────────────>│   │                                 └───┘                .───────────.
//   ────┼────            │   │     GET /challenge {user}         │                 (  Database   )
//       │                │   ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>┌───┐               (`───────────')
//      ┌┴┐               │   │                               ┌─┤   │<──────────────(`───────────')
//      │ │               │   │     step1(user,salt,verifier) │ │   │{salt,verifier}(`───────────')
//      │ │               │   │                               │ │   │                `───────────'
//    ──┘ └──             │   │                               └>│   │
//                        │   │            {salt,B}             │   │    store b     .───────────.
//                      ┌─┤   │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤   ├──────────────>(Session Cache)
//   step1(user,passwd) │ │   │                                 └─┬─┘               (`───────────')
//         step2(salt,B)│ │   │     POST /auth {user,A,M1}      ┌───┐     load b    (`───────────')
//                      └>│   ├────────────────────────────────>│   │<──────────────(`───────────')
//                        └───┘                               ┌─┤   │                `───────────'
//                          │                      step2(A,M1)│ │   │         ┌───────────────────┐
//                          |                                 │ │   │         │You have to retain │
//                        ┌─┴─┐             {M2}              └>│   │         │the private "b"    │
//               step3(M2)│   │<────────────────────────────────┤   │         │which matches the  │
//                        └─┬─┘                                 └─┬─┘         │public challenge   │
// ┌──────────────────────┐ |                                     |           │"B". This can be in│
// │step3 confirms a      │ │                                     │           │the main DB or a   │
// │shared private key. A │ |                                     |           │cache.             │
// │mobile running        │ │                                     │           └───────────────────┘
// │embedded JavaScript   │ ▼                                     ▼
// │also confirms the     │
// │server knows the      │
// │verifier that the user│
// │registered with.      │
// └──────────────────────┘
// based on: https://github.com/simbo1905/thinbus-srp-npm/blob/master/test/testrunner.js

/**
 * JSDoc typedefs to improve intellisense
 * @typedef {import('http').ClientRequest} ClientRequest
 * @typedef {import('http').ServerResponse} ServerResponse
 */

const status = require('statuses')
// RFC 5054 2048bit constants
const rfc5054 = {
  N_base10: '21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819',
  g_base10: '2',
  k_base16: '5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300'
}

// initialize the library using the RFC 5054 constants
const SRP6JavascriptClientSession = require('thinbus-srp/client.js')(rfc5054.N_base10, rfc5054.g_base10, rfc5054.k_base16)

// define fallbacks for testing (running on node instead of browser)
const fetch = (typeof window !== 'undefined' && 'fetch' in window) ? window.fetch : require('node-fetch')
const location = (typeof window !== 'undefined')
  ? `${window.location.protocol}//${window.location.host}${window.location.pathname}`
  : 'http://localhost/'

class ThinbusSRPClient {
  /**
   * Performs the login procedure
   * @param {string} username
   * @param {string} password
   * @throws an error if the password does not match or some other error occures
   * @returns {Promise<boolean>} promise for a boolean "true" on success (async function -> promise)
   */
  async login (username, password) {
    username = encodeURIComponent(username)

    const client = new SRP6JavascriptClientSession()
    const {salt, B} = await this.challenge(username)
    client.step1(username, password)
    const {A, M1} = client.step2(salt, B)
    const M2 = await this.authenticate(username, A, M1)
    // Check the server's verification message M2, throws if M2 does not match
    client.step3(M2)
    return true
  }

  /**
   * Retrieves the salt and the remote empheral random value B from the server, given the username
   * @param {string} username
   * @returns {Promise<{salt: string, B: string}>} promise for salt and B (hex-encoded)
   * @throws an error if there is no such user or if an error occures
   */
  challenge (username) {
    return this.fetch(`${location}challenge?user=${username}`)
      .then(response => {
        if (response.ok) return response.json()
        else throw new Error('challenge failed')
      })
  }

  /**
   * Authenticates the user to the server, using the username, the client's empheral random value A
   * and the previously computed verification message M1 and
   * @param {string} username
   * @param {string} A (hex-encoded)
   * @param {string} M1 (hex-encoded)
   * @returns {Promise<string>} promise for the server's verification message M2 (hex-encoded)
   */
  authenticate (username, A, M1) {
    return this.fetch(`${location}auth`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({user: username, A: A, M1: M1})
    })
      .then(response => {
        if (response.ok) return response.json()
        else throw new Error('invalid credentials')
      })
      .then(json => json.M2)
  }

  /**
   * Register the user to the server by generating the salt and the verifier
   * @param {string} username
   * @param {string} password
   * @throws an error if the username is already taken or if some other error occures
   * @returns {Promise<boolean>} promise for a boolean "true" on success
   */
  async register (username, password) {
    const client = new SRP6JavascriptClientSession()
    const salt = client.generateRandomSalt()
    const verifier = client.generateVerifier(salt, username, password)
    const response = await this.fetch(`${location}register`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({user: username, salt: salt, verifier: verifier})
    })

    if (response.ok && response.status === status('No Content')) return true
    else throw new Error(`registering failed (${await response.text()})`)
  }

  /**
   * 
   * @param {string} url 
   * @param {object} options 
   * @returns {Promise<ServerResponse>}
   */
  fetch(url, options) {
    options = options || {}
    options.headers = options.headers || {}
    // if not in browser, we have to handle cookies manually
    if (typeof window === 'undefined' && this.cookie) options.headers.Cookie = this.cookie
    return fetch(url, options)
      .then(rsp => {
        // if not in browser, extract and store cookie
        if(typeof window === 'undefined') {
          this.cookie = rsp.headers.raw()['set-cookie']
        }
        return rsp
      })
  }
}

// in browser mode save client to document, else export as module
if (typeof document !== 'undefined') document.ThinbusSRPClient = ThinbusSRPClient
else module.exports = ThinbusSRPClient
