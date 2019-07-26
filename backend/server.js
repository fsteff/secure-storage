const express = require('express')
const bodyParser = require('body-parser')
const session = require('express-session')
const MemoryStore = require('memorystore')(session)
const cryptoRandomString = require('crypto-random-string')

const thinbusSRP = require('./thinbus-srp-server').handleRequest
const port = 80

function createServer () {
  const app = express()
  const promise = new Promise((resolve, reject) => {
    try {
      app.use(bodyParser.json())
      app.use(session({
        secret: cryptoRandomString({length: 20}),
        resave: false,
        saveUninitialized: true,
        proxy: true,
        rolling: true,
        cookie: {
          httpOnly: true,
          secure: false,
          maxAge: 3600 * 24
        },
        store: new MemoryStore({
          checkPeriod: 86400000 // prune expired entries every 24h
        }),
        name: 'srp-tests-session'
      }))
      app.use(function headers (req, res, next) {
        res.set('Content-Security-Policy', 'script-src http://localhost;')
        next()
      })
      app.use(thinbusSRP)
      app.use(express.static('www'))

      const server = app.listen(port, () => {
        console.log(`Server listening on port ${port}!`)
        resolve(server)
      })
    } catch (exception) {
      reject(exception)
      console.error(exception)
    }
  })
  return promise
}

module.exports = createServer
