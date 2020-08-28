const express = require('express')
const bodyparser = require('body-parser')
const helmet = require('helmet')
const mongoose = require('mongoose')
const uniqid = require('uniqid')
const ratelimit = require('express-rate-limit')
const { body, validationResult } = require('express-validator')
const { join } = require('path')
const { createHash } = require('crypto')
require('dotenv').config({ path: join(__dirname, '.env') })

const app = express()
app.use(helmet())
app.use(require('sanitize').middleware)
app.use(bodyparser.json())
app.use(bodyparser.urlencoded({ extended: false }))
app.use(express.static('public'))

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(console.error)

const URL = require('./models/url.js')
const limiter = ratelimit({
  windowMs: 60 * 1000, // 1 min
  max: 25,
  message: 'Too many request from this IP'
})

app.get('/', async (req, res) => {
  return res.sendFile(join(__dirname, 'public', 'index.html'))
})

app.get('/:code', async (req, res) => {
  const code = req.params.code
  if (!code) {
    return res.status(422).json({
      message: 'Invalid code'
    })
  }

  const query = await URL.findOne({
    code
  }).exec()

  if (!query) {
    if (req.xhr) {
      return res.status(404).json({
        message: 'No URL with this code registered'
      })
    } else {
      return res.status(404).sendFile(join(__dirname, 'public', '404.html'))
    }
  }

  query.clicks += 1
  query.save().catch(console.error)

  return res.redirect(query.url)
})

app.post('/', limiter, [
  body('url').isURL(),
  body('code').optional().not().matches(/[^a-z0-9_\-+]/gi),
  body('expire').optional().isInt()
], async (req, res, next) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() })

  const url = req.body.url
  const code = req.body.code || createHash('md5').update(`${uniqid.time()}-${url}`).digest('hex').substring(0, 6)
  const expire = req.body.expire && req.body.expire > 0 ? req.body.expire : -1

  if (await URL.exists({ code })) {
    return res.status(409).json({
      message: 'This code is already used',
      code
    })
  }

  const accessCode = createHash('sha1').update(`${uniqid.time()}-${url}`).digest('hex')
  const ops = {
    id: createHash('md5').update(`${uniqid.time()}-${url}-${Date.now()}`).digest('hex'),
    code,
    url,
    expire,
    createdAt: new Date(),
    clicks: 0,
    accessCode
  }

  const newURL = new URL(ops)
  await newURL.save().catch(next)

  if (expire !== -1) {
    setTimeout(async () => await newURL.deleteOne({ code, accessCode }), expire)
  }

  return res.json({
    code,
    accessCode
  })
})

app.delete('/', limiter, [
  body('code').not().matches(/[^a-z0-9_\-+]/gi),
  body('accessCode').isHash('sha1')
], async (req, res, next) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() })

  const code = req.body.code
  const accessCode = req.body.accessCode

  if (!(await URL.exists({ code }))) {
    return res.status(404).json({
      message: 'No URL with this code registered'
    })
  }

  if (!(await URL.exists({ code, accessCode }))) {
    return res.status(403).json({
      message: 'Missing access to delete this code'
    })
  }

  await URL.deleteOne({
    code,
    accessCode
  }).exec().catch(next)

  return res.json({
    message: 'Successfully removed the URL from database'
  })
})

app.use(async (err, req, res, next) => {
  if (err.message.toLowerCase().includes('unexpected token') && err.message.toLowerCase().includes('json')) {
    return res.status(400).json({
      message: 'Invalid JSON body'
    })
  }
  console.error(err.stack, err.message)
  res.status(500).json({
    message: 'Something went wrong!'
  })
})

app.listen(process.env.PORT, () => console.log(`Listening to port ${process.env.PORT}`))
