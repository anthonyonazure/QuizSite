const crypto = require('crypto');

function generateRefreshTokenKey() {
  return crypto.randomBytes(64).toString('hex');
}

const refreshTokenKey = generateRefreshTokenKey();
console.log('Refresh Token Key:', refreshTokenKey);