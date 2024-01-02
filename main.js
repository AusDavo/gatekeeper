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

  const formatPath = (path) =>
    (path.match(pathsRegex) || ["unknown"])[0].replace(/h/g, "'");

  const associatedPathsAndXpubs = () => {
    const xpubs = extractMatches(xpubsRegex);
    const xpubFingerprints = extractMatches(xpubFingerprintRegex);
    const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

    return xpubs.map((xpub, index) => ({
      path: formatPath(parts[index]),
      xpub,
      xpubFingerprint: xpubFingerprints[index] || "unknown",
    }));
  };

  return associatedPathsAndXpubs();
}

function populateXpubDropdown(xpubsAndFingerprints) {
  const dropdown = document.getElementById("xpubDropdown");
  dropdown.innerHTML = ""; // Clear existing options

  xpubsAndFingerprints.forEach((entry) => {
    const { xpub, xpubFingerprint } = entry;

    const option = document.createElement("option");
    option.value = xpub;

    const shortXpub = `${xpub.slice(0, 10)}...${xpub.slice(-6)}`;
    const fingerprintFormatted =
      xpubFingerprint !== "unknown" ? ` (fingerprint: ${xpubFingerprint})` : "";

    option.innerHTML = `<strong>${shortXpub}</strong>${fingerprintFormatted}`;
    dropdown.appendChild(option);
  });
}

window.onload = function () {
  // Hide elements below xpub and the "Select xpub" dropdown when the page loads
  const hideElement = (elementId) => {
    const element = document.getElementById(elementId);
    if (element) {
      element.style.display = "none";
    }
  };

  hideElement("elementsBelowXpub");
  hideElement("xpubDropdownContainer");
};

window.extractXpubsAndPopulateDropdown = function () {
  const getElement = (id) => document.getElementById(id);
  const hideElement = (element) => (element.style.display = "none");
  const showElement = (element, displayType = "block") =>
    (element.style.display = displayType);

  const {
    multisigConfigInput,
    extractXpubsButton,
    importDescriptorButton,
    multisigLabel,
    xpubDropdownContainer,
    elementsBelowXpub,
    derivationPathResult,
    messageInput,
    signatureInput,
    evaluateSignatureButton,
  } = {
    multisigConfigInput: getElement("multisigConfigInput"),
    extractXpubsButton: getElement("extractXpubsButton"),
    importDescriptorButton: getElement("importDescriptorButton"),
    multisigLabel: getElement("multisigLabel"),
    xpubDropdownContainer: getElement("xpubDropdownContainer"),
    elementsBelowXpub: getElement("elementsBelowXpub"),
    derivationPathResult: getElement("derivationPathResult"),
    messageInput: getElement("messageInput"),
    signatureInput: getElement("signatureInput"),
    evaluateSignatureButton: getElement("evaluateSignatureButton"),
  };

  try {
    const associatedPathsAndXpubs = extractPathsAndXpubsFromMultisigConfig(
      multisigConfigInput.value
    );

    console.log("Associated Paths and XPubs:", associatedPathsAndXpubs);

    populateXpubDropdown(associatedPathsAndXpubs);

    showElement(xpubDropdownContainer);
    hideElement(elementsBelowXpub);

    const initialSelectedXpub = getElement("xpubDropdown").value;
    const initialSelectedEntry = associatedPathsAndXpubs.find(
      (entry) => entry.xpub === initialSelectedXpub
    );
    const initialFormattedPath = initialSelectedEntry
      ? initialSelectedEntry.path
      : "unknown";

    const initialSelectedAddress = bitcoinUtils.deriveAddress(
      initialSelectedXpub,
      0
    ).address;
    derivationPathResult.innerHTML = `Ask your multisig collaborator to sign a message with the private key for <strong>${initialSelectedAddress}</strong>. This is derived from the first child public key of the selected xpub. Its derivation path from your collaborator's BIP32 root key (m) is m${initialFormattedPath}/0.`;

    hideElement(multisigConfigInput);
    hideElement(extractXpubsButton);
    hideElement(multisigLabel);

    showElement(importDescriptorButton, "inline-block");

    const xpubDropdown = getElement("xpubDropdown");
    xpubDropdown.addEventListener("change", function () {
      const selectedXpub = this.value;
      const selectedEntry = associatedPathsAndXpubs.find(
        (entry) => entry.xpub === selectedXpub
      );
      const formattedPath = selectedEntry ? selectedEntry.path : "unknown";

      const selectedAddress = bitcoinUtils.deriveAddress(
        selectedXpub,
        0
      ).address;
      derivationPathResult.innerHTML = `The Bitcoin address <strong>${selectedAddress}</strong> is derived from the selected xpub. The key pair for this address originates from the first child keys under that xpub, following the BIP32 root key's path <strong>m${formattedPath}/0</strong>. To confirm your collaborator's continued key control in your multisig wallet, request them to sign a new message. Paste the returned signature in the box below and click the button for verification. A successful outcome indicates that your collaborator maintains control over their key for your shared multisig setup.`;

      showElement(elementsBelowXpub);
      showElement(messageInput, "inline-block");
      showElement(signatureInput, "inline-block");
      showElement(evaluateSignatureButton, "inline-block");
    });
  } catch (error) {
    console.error("Error during xpub extraction:", error.message);
  }
};

window.importMultisigDescriptor = function () {
  const getById = (id) => document.getElementById(id);
  const show = (element, displayType = "inline-block") =>
    (element.style.display = displayType);
  const hide = (element) => (element.style.display = "none");

  const {
    multisigConfigInput,
    extractXpubsButton,
    importDescriptorButton,
    multisigLabel,
    elementsBelowXpub,
    xpubDropdownContainer,
  } = {
    multisigConfigInput: getById("multisigConfigInput"),
    extractXpubsButton: getById("extractXpubsButton"),
    importDescriptorButton: getById("importDescriptorButton"),
    multisigLabel: getById("multisigLabel"),
    elementsBelowXpub: getById("elementsBelowXpub"),
    xpubDropdownContainer: getById("xpubDropdownContainer"),
  };

  // Show the original input, button, and label
  [multisigConfigInput, extractXpubsButton, multisigLabel].forEach((element) =>
    show(element)
  );

  // Hide the import button
  hide(importDescriptorButton);

  // Hide the elements below xpub and the "Select xpub" dropdown when importing
  [elementsBelowXpub, xpubDropdownContainer].forEach(hide);

  // Clear the existing input value
  multisigConfigInput.value = "";

  // Optionally, you can reset or hide other related elements as needed
};

window.evaluateSignature = function () {
  const getXpubDropdownValue = () =>
    document.getElementById("xpubDropdown").value;
  const getAddressFromXpub = (xpub) =>
    bitcoinUtils.deriveAddress(xpub, 0).address;

  const signatureInputValue = document.getElementById("signatureInput").value;
  const messageInputValue =
    document.getElementById("messageInput").value || "default";

  try {
    const selectedXpub = getXpubDropdownValue();
    const address = getAddressFromXpub(selectedXpub);

    const isValid = bitcoinUtils.validateSignature(
      messageInputValue,
      signatureInputValue,
      address
    );

    // Log the validation result
    logSignatureValidationResult(isValid);
  } catch (error) {
    console.error("Error during signature validation:", error.message);
    logSignatureValidationResult(false);
  }
};
