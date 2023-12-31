const bitcoinUtils = require('./bitcoin-utils');
let associatedPathsAndXpubs; // Declare it globally

function logSignatureValidationResult(isValid) {
  const resultElement = document.getElementById('validationResult');
  resultElement.textContent = isValid ? 'Signature is valid!' : 'Signature is NOT valid!';
}

function extractPathsAndXpubsFromMultisigConfig(multisigConfig) {
  const pathsRegex = /\/[\dh'\/]+(?:[h'](?=\d)|[h'])/g;
  const xpubsRegex = /\b\w*xpub\w*\b/g;

  const extractMatches = (regex) => [...multisigConfig.matchAll(regex)].map(match => match[0]);

  const associatedPathsAndXpubs = () => {
    const xpubs = extractMatches(xpubsRegex);
    const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

    const formatPath = (path) => (path.match(pathsRegex) || ['unknown'])[0].replace(/h/g, "'");

    return xpubs.map((xpub, index) => ({
      path: formatPath(parts[index]),
      xpub: xpub,
    }));
  };

  return associatedPathsAndXpubs();
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

window.extractXpubsAndPopulateDropdown = function () {
  const multisigConfigInput = document.getElementById('multisigConfigInput').value;

  try {
    // Use the new function to extract paths and XPubs
    associatedPathsAndXpubs = extractPathsAndXpubsFromMultisigConfig(multisigConfigInput);

    console.log('Associated Paths and XPubs:', associatedPathsAndXpubs);

    // Extract XPubs from the result for populating the dropdown
    const xpubs = associatedPathsAndXpubs.map(entry => entry.xpub);

    // Populate the dropdown menu with XPubs
    populateXpubDropdown(xpubs);

    // Display the dropdown menu
    document.getElementById('xpubDropdownContainer').style.display = 'block';

    // Set the initial value for derivationPathResult
    const initialSelectedXpub = document.getElementById('xpubDropdown').value;
    const initialSelectedEntry = associatedPathsAndXpubs.find(entry => entry.xpub === initialSelectedXpub);
    const initialFormattedPath = initialSelectedEntry ? initialSelectedEntry.path : 'unknown';
    document.getElementById('derivationPathResult').textContent = `Derivation Path: ${initialFormattedPath}`;

    // Add an event listener for the onchange event of the dropdown
    document.getElementById('xpubDropdown').addEventListener('change', function () {
      const selectedXpub = this.value;

      // Find the entry with the selected XPub from the result of extractPathsAndXpubs
      const selectedEntry = associatedPathsAndXpubs.find(entry => entry.xpub === selectedXpub);

      // Use the path from the selected entry
      const formattedPath = selectedEntry ? selectedEntry.path : 'unknown';

      // Set the content of the derivationPathResult element
      document.getElementById('derivationPathResult').textContent = `Derivation Path: ${formattedPath}`;
    });
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

    // Log the validation result
    logSignatureValidationResult(isValid);
  } catch (error) {
    console.error('Error during signature validation:', error.message);
    logSignatureValidationResult(false);
  }
};


