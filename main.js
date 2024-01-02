const bitcoinUtils = require("./bitcoin-utils");

let associatedPathsAndXpubs; // Declare it globally

function logSignatureValidationResult(isValid) {
  const resultElement = document.getElementById("validationResult");
  resultElement.textContent = isValid
    ? "Signature is valid!"
    : "Signature is NOT valid!";
}

function extractPathsAndXpubsFromMultisigConfig(multisigConfig) {
  const pathsRegex = /\/[\dh'\/]+(?:[h'](?=\d)|[h'])/g;
  const xpubsRegex = /\b\w*xpub\w*\b/g;
  const xpubFingerprintRegex = /\b[A-Fa-f0-9]{8}\b/g;

  const extractMatches = (regex) =>
    [...multisigConfig.matchAll(regex)].map((match) => match[0]);

  const associatedPathsAndXpubs = () => {
    const xpubs = extractMatches(xpubsRegex);
    const xpubFingerprints = extractMatches(xpubFingerprintRegex);
    const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

    const formatPath = (path) =>
      (path.match(pathsRegex) || ["unknown"])[0].replace(/h/g, "'");

    return xpubs.map((xpub, index) => ({
      path: formatPath(parts[index]),
      xpub: xpub,
      xpubFingerprint: xpubFingerprints[index] || "unknown",
    }));
  };

  return associatedPathsAndXpubs();
}

function populateXpubDropdown(xpubsAndFingerprints) {
  const dropdown = document.getElementById("xpubDropdown");
  dropdown.innerHTML = ""; // Clear existing options

  xpubsAndFingerprints.forEach((entry, index) => {
    const option = document.createElement("option");
    option.value = entry.xpub;

    // Limit the characters displayed before the ellipsis for the xpub
    const xpubFormatted = `${entry.xpub.slice(0, 10)}...${entry.xpub.slice(
      -6
    )}`;
    const fingerprintFormatted =
      entry.xpubFingerprint !== "unknown"
        ? ` (fingerprint: ${entry.xpubFingerprint})`
        : "";

    // Set the formatted string as the text content of the option
    option.innerHTML = `<strong>${xpubFormatted}</strong>${fingerprintFormatted}`;

    dropdown.appendChild(option);
  });
}

window.onload = function () {
  // Hide the elements below xpub and the "Select xpub" dropdown when the page loads
  const elementsBelowXpub = document.getElementById("elementsBelowXpub");
  const xpubDropdownContainer = document.getElementById(
    "xpubDropdownContainer"
  );
  elementsBelowXpub.style.display = "none";
  xpubDropdownContainer.style.display = "none";
};

window.extractXpubsAndPopulateDropdown = function () {
  const multisigConfigInput = document.getElementById("multisigConfigInput");
  const extractButton = document.getElementById("extractXpubsButton");
  const importButton = document.getElementById("importDescriptorButton");
  const multisigLabel = document.getElementById("multisigLabel");
  const xpubDropdownContainer = document.getElementById(
    "xpubDropdownContainer"
  );
  const elementsBelowXpub = document.getElementById("elementsBelowXpub");
  const derivationPathResult = document.getElementById("derivationPathResult");
  const messageInput = document.getElementById("messageInput");
  const signatureInput = document.getElementById("signatureInput");
  const evaluateSignatureButton = document.getElementById(
    "evaluateSignatureButton"
  );

  try {
    // Use the new function to extract paths and XPubs
    associatedPathsAndXpubs = extractPathsAndXpubsFromMultisigConfig(
      multisigConfigInput.value
    );

    console.log("Associated Paths and XPubs:", associatedPathsAndXpubs);

    // Populate the dropdown menu with XPubs and fingerprints
    populateXpubDropdown(associatedPathsAndXpubs);

    // Display the "Select xpub" dropdown and hide the elements below xpub
    xpubDropdownContainer.style.display = "block";
    elementsBelowXpub.style.display = "none";

    // Set the initial value for derivationPathResult
    const initialSelectedXpub = document.getElementById("xpubDropdown").value;
    const initialSelectedEntry = associatedPathsAndXpubs.find(
      (entry) => entry.xpub === initialSelectedXpub
    );
    const initialFormattedPath = initialSelectedEntry
      ? initialSelectedEntry.path
      : "unknown";

    // Modify the derivation path message
    const initialSelectedAddress = bitcoinUtils.deriveAddress(
      initialSelectedXpub,
      0
    ).address;
    derivationPathResult.innerHTML = `Ask your multisig collaborator to sign a message with the private key for <strong>${initialSelectedAddress}</strong>. This is derived from the first child public key of the selected xpub. Its derivation path from your collaborator's BIP32 root key (m) is m${initialFormattedPath}/0.`;

    // Hide the original input, button, and label
    multisigConfigInput.style.display = "none";
    extractButton.style.display = "none";
    multisigLabel.style.display = "none";

    // Show the import button
    importButton.style.display = "inline-block";

    // Add an event listener for the onchange event of the dropdown
    document
      .getElementById("xpubDropdown")
      .addEventListener("change", function () {
        const selectedXpub = this.value;

        // Find the entry with the selected XPub from the result of extractPathsAndXpubs
        const selectedEntry = associatedPathsAndXpubs.find(
          (entry) => entry.xpub === selectedXpub
        );

        // Use the path from the selected entry
        const formattedPath = selectedEntry ? selectedEntry.path : "unknown";

        // Modify the derivation path message
        const selectedAddress = bitcoinUtils.deriveAddress(
          selectedXpub,
          0
        ).address;
        derivationPathResult.innerHTML = `The Bitcoin address <strong>${selectedAddress}</strong> is derived from the selected xpub. The key pair for this address originates from the first child keys under that xpub, following the BIP32 root key's path <strong>m${formattedPath}/0</strong>. To confirm your collaborator's continued key control in your multisig wallet, request them to sign a new message. Paste the returned signature in the box below and click the button for verification. A successful outcome indicates that your collaborator maintains control over their key for your shared multisig setup.`;

        // Show the elements below xpub when an xpub is selected
        elementsBelowXpub.style.display = "block";

        // Show the message input, signature input, and interrogate xpub button
        messageInput.style.display = "inline-block";
        signatureInput.style.display = "inline-block";
        evaluateSignatureButton.style.display = "inline-block";
      });
  } catch (error) {
    console.error("Error during xpub extraction:", error.message);
  }
};

window.importMultisigDescriptor = function () {
  const multisigConfigInput = document.getElementById("multisigConfigInput");
  const extractButton = document.getElementById("extractXpubsButton");
  const importButton = document.getElementById("importDescriptorButton");
  const multisigLabel = document.getElementById("multisigLabel");
  const elementsBelowXpub = document.getElementById("elementsBelowXpub");
  const xpubDropdownContainer = document.getElementById(
    "xpubDropdownContainer"
  );
  const messageInput = document.getElementById("messageInput");
  const signatureInput = document.getElementById("signatureInput");
  const evaluateSignatureButton = document.getElementById(
    "evaluateSignatureButton"
  );

  // Show the original input, button, and label
  multisigConfigInput.style.display = "inline-block";
  extractButton.style.display = "inline-block";
  multisigLabel.style.display = "inline-block";

  // Hide the import button
  importButton.style.display = "none";

  // Hide the elements below xpub and the "Select xpub" dropdown when importing
  elementsBelowXpub.style.display = "none";
  xpubDropdownContainer.style.display = "none";

  // Clear the existing input value
  multisigConfigInput.value = "";

  // Optionally, you can reset or hide other related elements as needed
};

window.evaluateSignature = function () {
  const selectedXpub = document.getElementById("xpubDropdown").value;

  const { address } = bitcoinUtils.deriveAddress(selectedXpub, 0);
  const signatureInput = document.getElementById("signatureInput").value;
  const messageInput =
    document.getElementById("messageInput").value || "default";

  try {
    const isValid = bitcoinUtils.validateSignature(
      messageInput,
      signatureInput,
      address
    );

    // Log the validation result
    logSignatureValidationResult(isValid);
  } catch (error) {
    console.error("Error during signature validation:", error.message);
    logSignatureValidationResult(false);
  }
};
