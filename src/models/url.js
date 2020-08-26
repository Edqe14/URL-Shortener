const { Schema, model } = require('mongoose')

module.exports = model('url', Schema({
  id: String,
  code: String,
  url: String,
  expire: Number,
  createdAt: Date,
  clicks: Number,
  accessCode: String
}))
