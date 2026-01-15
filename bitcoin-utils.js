// bitcoin-utils.js
const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

const ADDRESS_TYPES = {
  legacy: 'legacy',      // P2PKH - starts with 1
  segwit: 'segwit',      // P2WPKH - starts with bc1q
};

function deriveAddress(xpub, index, addressType = ADDRESS_TYPES.legacy) {
  const node = bitcoin.bip32.fromBase58(xpub);
  const publicKeyBuffer = node.derive(index).publicKey;

  let payment;
  switch (addressType) {
    case ADDRESS_TYPES.segwit:
      payment = bitcoin.payments.p2wpkh({ pubkey: publicKeyBuffer });
      break;
    case ADDRESS_TYPES.legacy:
    default:
      payment = bitcoin.payments.p2pkh({ pubkey: publicKeyBuffer });
      break;
  }

  return { address: payment.address };
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
  ADDRESS_TYPES,
};
