const express = require('express')
const bodyparser = require('body-parser')
const helmet = require('helmet')
const mongoose = require('mongoose')
const { body, validationResult } = require('express-validator')
const uniqid = require('uniqid')
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

app.get('/', async (req, res) => {
  return res.sendFile(join(__dirname, 'public', 'index.html'))
})

app.get('/:code', async (req, res) => {
  const code = req.params.code
  if (!code) {
    return res.status(422).send({
      message: 'Invalid code'
    })
  }

  const query = await URL.findOne({
    code
  }).exec()

  if (!query) {
    return res.status(404).send({
      message: 'No URL with this code registered'
    })
  }

  query.clicks += 1
  query.save().catch(console.error)

  return res.redirect(query.url)
})

app.post('/', [
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
    return res.status(409).send({
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

  return res.send({
    code,
    accessCode
  })
})

app.delete('/', [
  body('code').not().matches(/[^a-z0-9_\-+]/gi),
  body('accessCode').isHash('sha1')
], async (req, res, next) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() })

  const code = req.body.code
  const accessCode = req.body.accessCode

  if (!(await URL.exists({ code }))) {
    return res.status(404).send({
      message: 'No URL with this code registered'
    })
  }

  if (!(await URL.exists({ code, accessCode }))) {
    return res.status(403).send({
      message: 'Missing access to delete this code'
    })
  }

  await URL.deleteOne({
    code,
    accessCode
  }).exec().catch(next)

  return res.send({
    message: 'Successfully removed the URL from database'
  })
})

app.use((err, req, res, next) => {
  console.error(err.stack, err.message)
  res.status(500).send('Something went wrong!')
})

app.listen(process.env.PORT, () => console.log(`Listening to port ${process.env.PORT}`))
