const express = require('express')
const axios = require('axios');
const NodeRSA = require('node-rsa');
const jsonwebtoken = require('jsonwebtoken');

const app = express()

app.listen(8000, () => console.log('Servidor conectado na porta 8000'))

async function _getApplePublicKeys() {
  return axios
    .request({
      method: 'GET',
      url: 'https://appleid.apple.com/auth/keys',
    })
    .then(response => response.data.keys);
}

const getAppleUserId = async token => {
  const keys = await _getApplePublicKeys();
  const decodedToken = jsonwebtoken.decode(token, { complete: true });
  const kid = decodedToken.header.kid;
  const key = keys.find(k => k.kid === kid);

  const pubKey = new NodeRSA();
  pubKey.importKey(
    { n: Buffer.from(key.n, 'base64'), e: Buffer.from(key.e, 'base64') },
    'components-public'
  );
  const userKey = pubKey.exportKey(['public']);

  return jsonwebtoken.verify(token, userKey, {
    algorithms: 'RS256',
  });
};

app.use('/apple/callback', async function (req, res) {
  await getAppleUserId(req.body.id_token);
  res.redirect(303, 'http://localhost:9000/');
});