(function() {
  var checkHash, decrypt, decrypted, encrypt, encrypted, generateToken, hash, hashPassword, parseToken, parsedId, password, token, userId;

  ({encrypt, decrypt, hashPassword, checkHash, generateToken, parseToken} = require('../index')({
    encryptionKey: '135x!'
  })({
    config: {}
  }));

  userId = new Date().valueOf().toString(23);

  console.log('userId', userId);

  encrypted = encrypt(userId);

  console.log('encrypted', encrypted);

  decrypted = decrypt(encrypted);

  console.log('decrypted', decrypted);

  password = "monkey123";

  console.log('password', password);

  hash = hashPassword(password);

  console.log('hash', hash);

  console.log('pass matches hash =', checkHash(password, hash));

  token = generateToken(userId, 4);

  console.log('token', token);

  parsedId = parseToken(token);

  console.log('parsed userId', parsedId);

}).call(this);

//# sourceMappingURL=test.js.map
