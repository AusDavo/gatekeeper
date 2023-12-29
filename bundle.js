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

function logSignatureValidationResult(isValid) {
  console.log(isValid ? 'Signature is valid!' : 'Signature is NOT valid!');
}

// Example usage:
const xpub = 'xpub6FQywvvaYNWevawA3PkVMa7mmpP17zPkzKew18NZvQqjw9Q2ixyKwzoowVVgmmrHveDEwioLSRf6kvSEmjLqpgQY44pki8iKU6wXKeHBLKc';
const index = 0;

const { address } = deriveAddress(xpub, index);
console.log('Corresponding Bitcoin Address:', address);

// Example signature validation:
const textToSign = 'test';
const signature = 'ICS0jkidZe+rvBfg/eXgzmCMelTGAT5/PAJ3EJcK8luIPEHxZ/FpfknidQjf0qn5x2SvkH7FCGLcxliGWdOT11w=';

try {
  logSignatureValidationResult(validateSignature(textToSign, signature, address));
} catch (error) {
  console.error('Error during signature validation:', error.message);
}
