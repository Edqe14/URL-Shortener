const { Schema, model } = require('mongoose')

module.exports = model(process.env.NODE_ENV !== 'development' ? 'url' : 'urltest', Schema({
  id: String,
  code: String,
  url: String,
  expire: Number,
  createdAt: Date,
  clicks: Number,
  accessCode: String
}))
