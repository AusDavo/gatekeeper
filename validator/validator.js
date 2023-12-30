
const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

console.log('Script is running')


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

function deriveAndValidate() {
    const xpub = document.getElementById('xpub').value;
    const signature = document.getElementById('signature').value;
    const path = document.getElementById('path').value;

    try {
        const { address } = deriveAddress(xpub, path);
        const textToSign = 'test';
        const isValid = validateSignature(textToSign, signature, address);

        const resultMessage = isValid ? 'Signature is valid!' : 'Signature is NOT valid!';
        document.getElementById('result').innerText = resultMessage;
    } catch (error) {
        document.getElementById('result').innerText = 'Error during signature validation: ' + error.message;
    }
}