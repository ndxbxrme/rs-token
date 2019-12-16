bcrypt = require 'bcrypt-nodejs'
crypto = require 'crypto'

module.exports = (config) ->
  (rs) ->
    config = config or {}
    algorithm = config.algorithm or rs.config.algorithm or 'aes-256-ctr'
    encryptionKey = Buffer.alloc 32
    iv = Buffer.alloc 16, 0
    encryptionKey = Buffer.concat [Buffer.from(config.encryptionKey or rs.config.encryptionKey)], encryptionKey.length
    radix = config.radix or 23
    encrypt = (text) ->
      cipher = crypto.createCipheriv algorithm, encryptionKey, iv
      encrypted = cipher.update text, 'utf8', 'hex'
      encrypted += cipher.final 'hex'
      encrypted
    decrypt = (text) ->
      decipher = crypto.createDecipheriv algorithm, encryptionKey, iv
      decrypted = decipher.update text, 'hex', 'utf8'
      decrypted += decipher.final 'utf8'
      decrypted
    hashPassword = (password) ->
      bcrypt.hashSync password, bcrypt.genSaltSync(8), null
    checkHash = (password, hash) ->
      bcrypt.compareSync password, hash
    generateToken = (userId, expiresHours) ->
      expiryDate = new Date(new Date().valueOf() + expiresHours * 60 * 60 * 1000)
      expires = (expiryDate.valueOf() - new Date(2019,0,1).valueOf()).toString(radix)
      rawToken = userId + ':' + expires
      encrypt rawToken
    parseToken = (token) ->
      if token
        rawToken = decrypt token
        [userId, expires] = rawToken.split ':'
        expiryDate = new Date(parseInt(expires, radix) + new Date(2019,0,1).valueOf())
        if expiryDate > new Date()
          return userId
      null 
    rs.token =
      encrypt: encrypt
      decrypt: decrypt
      hashPassword: hashPassword
      checkHash: checkHash
      generateToken: generateToken
      parseToken: parseToken