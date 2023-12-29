// bundled.js
const bitcoinUtils = require('./bitcoin-utils');

function logSignatureValidationResult(isValid) {
  const resultElement = document.getElementById('validationResult');
  resultElement.textContent = isValid ? 'Signature is valid!' : 'Signature is NOT valid!';
}

function extractXpubsFromMultisigConfig(multisigConfig) {
  const regex = /\b\w*xpub\w*\b/g;
  const xpubs = [...multisigConfig.matchAll(regex)].map(match => match[0]);
  return xpubs;
}

function populateXpubDropdown(xpubs) {
  const dropdown = document.getElementById('xpubDropdown');
  dropdown.innerHTML = ''; // Clear existing options

  xpubs.forEach((xpub, index) => {
    const option = document.createElement('option');
    option.value = xpub;
    option.textContent = xpub;
    dropdown.appendChild(option);
  });
}

// Expose the function globally
window.extractXpubsAndPopulateDropdown = function () {
  const multisigConfigInput = document.getElementById('multisigConfigInput').value;

  try {
    const xpubs = extractXpubsFromMultisigConfig(multisigConfigInput);
    
    // Populate the dropdown menu with xpubs
    populateXpubDropdown(xpubs);

    // Display the dropdown menu
    document.getElementById('xpubDropdownContainer').style.display = 'block';
  } catch (error) {
    console.error('Error during xpub extraction:', error.message);
  }
};

window.interrogateXpub = function () {
  const selectedXpub = document.getElementById('xpubDropdown').value;
  const { address } = bitcoinUtils.deriveAddress(selectedXpub, 0);
  const signatureInput = document.getElementById('signatureInput').value;
  const messageInput = document.getElementById('messageInput').value || 'default';

  try {
    const isValid = bitcoinUtils.validateSignature(messageInput, signatureInput, address);
    logSignatureValidationResult(isValid);
  } catch (error) {
    console.error('Error during signature validation:', error.message);
    logSignatureValidationResult(false);
  }
};
