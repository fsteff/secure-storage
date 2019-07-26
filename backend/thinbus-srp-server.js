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

const fsp = require('fs').promises
const status = require('statuses')

/**
 * JSDoc typedefs to improve intellisense
 * @typedef {import('http').ClientRequest} ClientRequest
 * @typedef {import('http').ServerResponse} ServerResponse
 */

// RFC 5054 2048bit constants
const rfc5054 = {
  N_base10: '21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819',
  g_base10: '2',
  k_base16: '5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300'
}

// storage path for the local user "DB"
const STORAGE_PATH = './thinbus-srp.db.json'
// local user "DB"
let users = null

// generate the server session class from the server session factory closure
const SRP6JavascriptServerSession = require('thinbus-srp/server.js')(rfc5054.N_base10, rfc5054.g_base10, rfc5054.k_base16)

/**
 * Loads a user's entry of the local "DB"
 * @param {string} username
 * @returns {Promise<{salt: string, verifier: string}>} promise of object containing the hex-encoded salt and verifier
 */
async function getUser (username) {
  // if already in memory, return the value immediately
  if (users) return users[username]
  // else the file has to be loaded first
  try {
    const file = await fsp.readFile(STORAGE_PATH, {encoding: 'utf8'})
    users = JSON.parse(file)
    return users[username]
  } catch (err) {
    console.log(`unable to read file ${STORAGE_PATH}, create empty user database`)
    users = {}
    return null
  }
}

/**
 * Adds/overwrites a user's entry of the local "DB" and writes it to the JSON file
 * @param {string} username
 * @param {string} salt
 * @param {string} verifier
 */
function saveUser (username, salt, verifier) {
  users[username] = {salt: salt, verifier: verifier}
  return fsp.writeFile(STORAGE_PATH, JSON.stringify(users), {encoding: 'utf8'})
}

/**
 * Serves /challenge - Step 1 of the SRP protocol
 * 1) Retrieves the salt and verifier for the requested user
 * 2) Sets up a new SRP6 server session
 * 3) Generates the server's random empheral value B
 * 4) Stores the SRP6 server session to the (server-side in-memory) session storage
 * 5) Returns the user's salt and B to the client
 *
 * If the request is invalid or the requested user is unknown, an appropriate HTTP error code is sent to the client.
 *
 * @param {ClientRequest} req
 * @param {ServerResponse} res
 */
async function challenge (req, res) {
  const username = req.query.user
  if (req.method !== 'GET' || !username) {
    return res.status(status('Bad Request')).send('Missing parameter or wrong method type')
  }
  const user = await getUser(username)
  if (!user) {
    return res.status(status('Not Found')).send('User not found')
  }

  const server = new SRP6JavascriptServerSession()
  const B = server.step1(username, user.salt, user.verifier)

  // save this to the session storage
  req.session.serverSession = server.toPrivateStoreState()

  const data = JSON.stringify({
    salt: user.salt,
    B: B
  })
  res.setHeader('Content-Type', 'application/json')
  res.send(data)
}

/**
 * Serves /auth - Step 2 of the SRP protocol
 * 1) Load the SRP server session from the (server-side in-memory) session storage
 * 2) Calculate M2 using the provided client's empheral random value A and verification message M1 (= checks password)
 * 3) If the verification was successful, return M2 to confirm the successful login
 *
 * If the request is invalid or no valid session is found, an appropriate HTTP error code is sent to the client.
 * On success, the session's loggedIn value is set to true.
 *
 * @param {ClientRequest} req
 * @param {ServerResponse} res
 */
async function auth (req, res) {
  const username = req.body.user
  const A = req.body.A
  const M1 = req.body.M1
  if (req.method !== 'POST' ||
    !username ||
    !A ||
    !M1) {
    return res.status(status('Bad Request')).send('Missing parameter or invalid method type')
  }

  if (!req.session.serverSession) {
    // no valid session, needs to call /challenge first
    // might also happen if the session cookie has been blocked
    return res.status(status('Forbidden')).send('Called ./auth before ./challenge')
  }

  const server = new SRP6JavascriptServerSession()
  server.fromPrivateStoreState(req.session.serverSession)

  try {
    // throws if provided credentials are wrong
    const M2 = server.step2(A, M1)
    // success -> loggedIn = true
    req.session.loggedIn = true
    delete req.session.server // not needed anymore

    // return M2 to the client
    const data = JSON.stringify({ M2: M2 })
    res.setHeader('Content-Type', 'application/json')
    res.send(data)
  } catch (err) {
    console.warn(err)
    req.session.loggedIn = false
    return res.status(status('Unauthorized')).end('Invalid credentials')
  }
}

/**
 * Registration procedure - saves salt and verifier to the user "DB"
 * If the request is invalid or the user already exists, an appropriate HTTP error code is sent to the client.
 * @param {ClientRequest} req
 * @param {ServerResponse} res
 */
async function register (req, res) {
  const user = req.body.user
  const salt = req.body.salt
  const verifier = req.body.verifier

  if (req.method !== 'POST' ||
    !user ||
    !salt ||
    !verifier) {
    return res.status(status('Bad Request')).send('Missing parameter or invalid method type')
  }
  if (await getUser(user)) {
    // user is already registered
    return res.status(status('Forbidden')).send('User already exists')
  }

  await saveUser(user, salt, verifier)
  res.status(status('No Content')).end()
}

/**
 * Handles all SRP requests and forwards others to the next route handler
 * @param {ClientRequest} req
 * @param {ServerResponse} res
 * @param {function()} next route handler
 */
function handleRequest (req, res, next) {
  switch (req.path) {
    case '/challenge':
      challenge(req, res).catch(onError)
      break
    case '/auth':
      auth(req, res).catch(onError)
      break
    case '/register':
      register(req, res).catch(onError)
      break
    default:
      next()
  }

  /**
   * Called on internal errors -> log and return code 500
   * @param {Error} err
   */
  function onError (err) {
    console.error(err.message)
    res.status(status('Internal Server Error')).end()
  }
}

module.exports = {
  handleRequest: handleRequest,
  // for testing:
  challenge: challenge,
  auth: auth,
  register: register,
  STORAGE_PATH: STORAGE_PATH,
  cleanup: () => users = null
}
