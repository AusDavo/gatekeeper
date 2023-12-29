// bitcoin-utils.js
const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

function deriveAddress(xpub, index) {
  const node = bitcoin.bip32.fromBase58(xpub);
  const publicKeyBuffer = node.derive(index).publicKey;
  const address = bitcoin.payments.p2pkh({ pubkey: publicKeyBuffer }).address;

  return { address };
}

function base64UrlDecode(base64Url) {
  return Buffer.from(base64Url.replace(/_/g, '/').replace(/-/g, '+'), 'base64');
}

function validateSignature(text, signature, address) {
  const decodedSignature = base64UrlDecode(signature);
  const addressString = String(address);

  return bitcoinMessage.verify(text, addressString, decodedSignature);
}

module.exports = {
  deriveAddress,
  base64UrlDecode,
  validateSignature,
};
