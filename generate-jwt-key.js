const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const key = crypto.randomBytes(64).toString('hex');
const envPath = path.join(__dirname, '.env');

fs.appendFileSync(envPath, `\nTOKEN_SECRET=${key}\n`);
console.log(`JWT secret key criada e salva em .env: ${key}`);