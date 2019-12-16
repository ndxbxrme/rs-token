(function() {
  var bcrypt, crypto;

  bcrypt = require('bcrypt-nodejs');

  crypto = require('crypto');

  module.exports = function(config) {
    return function(rs) {
      var algorithm, checkHash, decrypt, encrypt, encryptionKey, generateToken, hashPassword, iv, parseToken, radix;
      config = config || {};
      algorithm = config.algorithm || rs.config.algorithm || 'aes-256-ctr';
      encryptionKey = Buffer.alloc(32);
      iv = Buffer.alloc(16, 0);
      encryptionKey = Buffer.concat([Buffer.from(config.encryptionKey || rs.config.encryptionKey)], encryptionKey.length);
      radix = config.radix || 23;
      encrypt = function(text) {
        var cipher, encrypted;
        cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
        encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
      };
      decrypt = function(text) {
        var decipher, decrypted;
        decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
        decrypted = decipher.update(text, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
      };
      hashPassword = function(password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
      };
      checkHash = function(password, hash) {
        return bcrypt.compareSync(password, hash);
      };
      generateToken = function(userId, expiresHours) {
        var expires, expiryDate, rawToken;
        expiryDate = new Date(new Date().valueOf() + expiresHours * 60 * 60 * 1000);
        expires = (expiryDate.valueOf() - new Date(2019, 0, 1).valueOf()).toString(radix);
        rawToken = userId + ':' + expires;
        return encrypt(rawToken);
      };
      parseToken = function(token) {
        var expires, expiryDate, rawToken, userId;
        if (token) {
          rawToken = decrypt(token);
          [userId, expires] = rawToken.split(':');
          expiryDate = new Date(parseInt(expires, radix) + new Date(2019, 0, 1).valueOf());
          if (expiryDate > new Date()) {
            return userId;
          }
        }
        return null;
      };
      return rs.token = {
        encrypt: encrypt,
        decrypt: decrypt,
        hashPassword: hashPassword,
        checkHash: checkHash,
        generateToken: generateToken,
        parseToken: parseToken
      };
    };
  };

}).call(this);

//# sourceMappingURL=index.js.map
