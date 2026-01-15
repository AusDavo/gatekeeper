const bitcoinUtils = require("../bitcoin-utils");
const uiInteraction = require("./ui-interaction");

const associatedPathsAndXpubs = [];
let selectedXpub = null;

const pathsRegex = /\/[\dh'\/]+(?:[h'](?=\d)|[h'])/g;
const xpubsRegex = /\b\w*xpub\w*\b/g;
const xpubFingerprintRegex = /\b[A-Fa-f0-9]{8}\b/g;

const extractMatches = (regex, input) =>
  [...input.matchAll(regex)].map((match) => match[0]);

const formatPath = (path) =>
  (path.match(pathsRegex) || ["unknown"])[0].replace(/h/g, "'");

const getElement = (id) => document.getElementById(id);

function showElements(elementsToShow, displayType = "flex") {
  (Array.isArray(elementsToShow) ? elementsToShow : [elementsToShow]).forEach(
    (element) => (element.style.display = displayType)
  );
}

function hideElements(elementsToHide) {
  (Array.isArray(elementsToHide) ? elementsToHide : [elementsToHide]).forEach(
    (element) => (element.style.display = "none")
  );
}

const extractPathsAndXpubsFromMultisigConfig = (multisigConfig) => {
  const xpubs = extractMatches(xpubsRegex, multisigConfig);
  const xpubFingerprints = extractMatches(xpubFingerprintRegex, multisigConfig);
  const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

  return xpubs.map((xpub, index) => ({
    path: formatPath(parts[index]),
    xpub,
    xpubFingerprint: xpubFingerprints[index] || "unknown",
  }));
};

const createRadioButton = (index, entry) => {
  const radioBtn = document.createElement("input");
  radioBtn.type = "radio";
  radioBtn.name = "xpubRadio";
  radioBtn.value = entry.xpub;
  radioBtn.id = `xpubRadio${index + 1}`;

  const label = document.createElement("label");
  label.htmlFor = `xpubRadio${index + 1}`;

  const shortXpub = `${entry.xpub.slice(0, 10)}...${entry.xpub.slice(-6)}`;
  const fingerprintFormatted =
    entry.xpubFingerprint !== "unknown"
      ? ` (fingerprint: ${entry.xpubFingerprint})`
      : "";

  label.textContent = `${shortXpub}${fingerprintFormatted}`;

  return { radioBtn, label };
};

const populateXpubRadioLabels = (xpubsAndFingerprints, container) => {
  container.innerHTML = "";
  xpubsAndFingerprints.forEach((entry, index) => {
    const { radioBtn, label } = createRadioButton(index, entry);

    container.appendChild(radioBtn);
    container.appendChild(label);
    container.appendChild(document.createElement("br"));
  });
};

function getDerivationSettings() {
  const addressType = getElement("addressTypeSelect").value;
  const childIndex = parseInt(getElement("childIndexInput").value, 10) || 0;
  return { addressType, childIndex };
}

function updateDerivationDisplay() {
  if (!selectedXpub) return;

  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === selectedXpub
  );
  const formattedPath = selectedEntry ? selectedEntry.path : "unknown";
  const { addressType, childIndex } = getDerivationSettings();

  const selectedAddress = bitcoinUtils.deriveAddress(
    selectedXpub,
    childIndex,
    addressType
  ).address;

  const addressTypeLabel =
    addressType === "segwit" ? "Native SegWit (P2WPKH)" : "Legacy (P2PKH)";

  const derivationPathResult = getElement("derivationPathResult");
  derivationPathResult.innerHTML = `
    <strong>${addressTypeLabel}</strong> address at child index <strong>${childIndex}</strong>:<br>
    <strong>${selectedAddress}</strong><br>
    Your collaborator can derive its corresponding private key from the BIP32 root key using this path:<br>
    <strong>m${formattedPath}/${childIndex}</strong><br>
    Ask your collaborator to sign a message using this key. Paste the returned signature below to verify.
  `;

  uiInteraction.clearValidationStatement();
}

function setupDerivationControlListeners() {
  const addressTypeSelect = getElement("addressTypeSelect");
  const childIndexInput = getElement("childIndexInput");

  addressTypeSelect.addEventListener("change", updateDerivationDisplay);
  childIndexInput.addEventListener("input", updateDerivationDisplay);
}

const handleXpubRadioChange = (event) => {
  selectedXpub = event.target.value;
  if (selectedXpub) {
    showElements(getElement("elementsBelowXpub"));
    showElements(getElement("copyButton"), "flex");
    updateDerivationDisplay();
    setupDerivationControlListeners();

    const copyButton = getElement("copyButton");
    copyButton.onclick = async function () {
      const textToCopy = generateExportText(selectedXpub);
      try {
        await navigator.clipboard.writeText(textToCopy);
        uiInteraction.showCopySuccessNotification();
      } catch (err) {
        console.error("Unable to copy to clipboard", err);
      }
    };
  }
};

function extractXpubsAndPopulateRadioButtons() {
  const xpubRadioContainer = getElement("xpubRadioContainer");

  const { multisigSection, importDescriptorButton } = {
    multisigSection: getElement("multisigSection"),
    importDescriptorButton: getElement("importDescriptorButton"),
  };

  try {
    associatedPathsAndXpubs.length = 0;
    associatedPathsAndXpubs.push(
      ...extractPathsAndXpubsFromMultisigConfig(multisigConfigInput.value)
    );

    if (associatedPathsAndXpubs.length === 0) {
      console.error("No xpubs found in descriptor");
      return;
    }

    showElements(importDescriptorButton);
    showElements(xpubRadioContainer);
    populateXpubRadioLabels(associatedPathsAndXpubs, xpubRadioContainer);
    xpubRadioContainer.addEventListener("change", handleXpubRadioChange);
  } catch (error) {
    console.error("Error during xpub extraction:", error.message);
  }

  hideElements(multisigSection);
}

function importMultisigDescriptor() {
  const {
    multisigSection,
    extractXpubsButton,
    elementsBelowXpub,
    xpubRadioContainer,
    importDescriptorButton,
  } = {
    multisigSection: getElement("multisigSection"),
    extractXpubsButton: getElement("extractXpubsButton"),
    elementsBelowXpub: getElement("elementsBelowXpub"),
    xpubRadioContainer: getElement("xpubRadioContainer"),
    importDescriptorButton: getElement("importDescriptorButton"),
  };

  showElements([multisigSection, extractXpubsButton]);
  hideElements([elementsBelowXpub, xpubRadioContainer, importDescriptorButton]);

  // Reset state
  selectedXpub = null;
  multisigConfigInput.value = "";
  getElement("addressTypeSelect").value = "legacy";
  getElement("childIndexInput").value = "0";
}

const logSignatureValidationResult = (isValid, errorMessage) => {
  const resultElement = getElement("validationResult");

  if (isValid) {
    resultElement.textContent = "Signature is valid!";
    resultElement.classList.add("success");
  } else {
    resultElement.textContent = errorMessage || "Signature is NOT valid!";
    resultElement.classList.remove("success");
  }
};

function evaluateSignature() {
  const { addressType, childIndex } = getDerivationSettings();

  const getAddressFromXpub = (xpub) =>
    bitcoinUtils.deriveAddress(xpub, childIndex, addressType).address;

  const signatureInputValue = getElement("signatureInput").value;
  const messageInputValue = getElement("messageInput").value || "default";

  const selectedRadio = document.querySelector(
    'input[name="xpubRadio"]:checked'
  );

  try {
    let currentXpub;
    if (selectedRadio) {
      const index = parseInt(selectedRadio.id.replace("xpubRadio", "")) - 1;
      currentXpub = associatedPathsAndXpubs[index].xpub;
    } else {
      throw new Error("No xpub selected");
    }

    const address = getAddressFromXpub(currentXpub);

    if (signatureInputValue.length === 0) {
      throw new Error("Signature is absent");
    } else if (signatureInputValue.length % 2 !== 0) {
      throw new Error("Invalid signature length");
    }

    const isValid = bitcoinUtils.validateSignature(
      messageInputValue,
      signatureInputValue,
      address
    );

    logSignatureValidationResult(isValid);
  } catch (error) {
    if (
      error.message === "Invalid signature length" ||
      error.message === "Signature is absent"
    ) {
      logSignatureValidationResult(false, error.message);
    } else {
      logSignatureValidationResult(false, "An unexpected error occurred.");
    }
  }
}

function generateExportText(xpub) {
  const messageInputValue = getElement("messageInput").value || "";
  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === xpub
  );
  const formattedPath = selectedEntry ? selectedEntry.path : "unknown";
  const { childIndex } = getDerivationSettings();

  return `${messageInputValue}\nm${formattedPath}/${childIndex}`;
}

function exportToFile() {
  const textToExport = generateExportText(selectedXpub);

  if (textToExport) {
    const blob = new Blob([textToExport], { type: "text/plain" });
    const a = document.createElement("a");
    const fileName = "challenge.txt";

    a.href = window.URL.createObjectURL(blob);
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
}

module.exports = {
  extractPathsAndXpubsFromMultisigConfig,
  populateXpubRadioLabels,
  extractXpubsAndPopulateRadioButtons,
  importMultisigDescriptor,
  evaluateSignature,
  generateExportText,
  exportToFile,
};
