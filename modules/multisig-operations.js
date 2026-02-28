const bitcoinUtils = require("../bitcoin-utils");
const uiInteraction = require("./ui-interaction");
const QRCode = require("qrcode");

const associatedPathsAndXpubs = [];
let selectedXpub = null;
const verificationResults = new Map();

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
  const relativePath = getElement("relativePathInput").value.trim();
  const signatureFormat = getElement("signatureFormatSelect").value;
  return { addressType, relativePath, signatureFormat };
}

function updateCompatibilityWarning() {
  const { addressType, signatureFormat } = getDerivationSettings();
  const warning = getElement("taprootWarning");
  const evaluateButton = getElement("evaluateSignatureButton");

  const compatibility = bitcoinUtils.getFormatCompatibility(
    signatureFormat,
    addressType
  );

  if (!compatibility.compatible) {
    warning.textContent = compatibility.note;
    warning.classList.add("visible");
    evaluateButton.disabled = true;
    evaluateButton.title = compatibility.note;
  } else {
    warning.classList.remove("visible");
    evaluateButton.disabled = false;
    evaluateButton.title = "";
  }
}

function updateDerivationDisplay() {
  if (!selectedXpub) return;

  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === selectedXpub
  );
  const basePath = selectedEntry ? selectedEntry.path : "unknown";
  const { addressType, relativePath } = getDerivationSettings();

  // Update compatibility warning
  updateCompatibilityWarning();

  try {
    const result = bitcoinUtils.deriveAddress(
      selectedXpub,
      relativePath,
      addressType
    );

    const addressTypeLabels = {
      legacy: "Legacy (P2PKH)",
      "segwit-wrapped": "Wrapped SegWit (P2SH-P2WPKH)",
      segwit: "Native SegWit (P2WPKH)",
      taproot: "Taproot (P2TR)",
    };

    // Build full path display
    const fullPath = relativePath
      ? `m${basePath}/${relativePath}`
      : `m${basePath}`;

    const derivationPathResult = getElement("derivationPathResult");
    derivationPathResult.innerHTML = `
      <div class="path-info">
        <span class="path-label">Base path from descriptor:</span>
        <strong>m${basePath}</strong>
      </div>
      <div class="path-info">
        <span class="path-label">Full derivation path:</span>
        <strong>${fullPath}</strong>
      </div>
      <div class="path-info">
        <span class="path-label">${addressTypeLabels[addressType]} address:</span>
        <strong class="address">${result.address}</strong>
      </div>
      <p class="instructions">
        Ask your collaborator to sign a message using the private key at this path, then paste the signature below to verify.
      </p>
    `;

    derivationPathResult.classList.remove("error");
  } catch (error) {
    const derivationPathResult = getElement("derivationPathResult");
    derivationPathResult.innerHTML = `
      <div class="error-message">
        <i class="fa-solid fa-circle-exclamation"></i>
        ${error.message}
      </div>
    `;
    derivationPathResult.classList.add("error");
  }

  uiInteraction.clearValidationStatement();
}

function setupDerivationControlListeners() {
  const addressTypeSelect = getElement("addressTypeSelect");
  const relativePathInput = getElement("relativePathInput");
  const signatureFormatSelect = getElement("signatureFormatSelect");

  // Remove old listeners by cloning
  const newAddressSelect = addressTypeSelect.cloneNode(true);
  const newPathInput = relativePathInput.cloneNode(true);
  const newFormatSelect = signatureFormatSelect.cloneNode(true);

  addressTypeSelect.parentNode.replaceChild(newAddressSelect, addressTypeSelect);
  relativePathInput.parentNode.replaceChild(newPathInput, relativePathInput);
  signatureFormatSelect.parentNode.replaceChild(newFormatSelect, signatureFormatSelect);

  newAddressSelect.addEventListener("change", updateDerivationDisplay);
  newPathInput.addEventListener("input", updateDerivationDisplay);
  newFormatSelect.addEventListener("change", updateCompatibilityWarning);
}

const handleXpubRadioChange = (event) => {
  selectedXpub = event.target.value;
  if (selectedXpub) {
    showElements(getElement("elementsBelowXpub"));
    showElements(getElement("copyButton"), "flex");
    setupDerivationControlListeners();
    updateDerivationDisplay();

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

    verificationResults.clear();
    showElements(importDescriptorButton);
    showElements(xpubRadioContainer);
    populateXpubRadioLabels(associatedPathsAndXpubs, xpubRadioContainer);
    updateProgressIndicator();
    updateReceiptButtonVisibility();
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
  verificationResults.clear();
  updateReceiptButtonVisibility();
  selectedXpub = null;
  multisigConfigInput.value = "";
  getElement("addressTypeSelect").value = "legacy";
  getElement("relativePathInput").value = "0/0";
  getElement("signatureFormatSelect").value = "electrum";
  getElement("taprootWarning").classList.remove("visible");
}

function updateRadioLabelStatus(xpub) {
  const index = associatedPathsAndXpubs.findIndex((e) => e.xpub === xpub);
  if (index === -1) return;
  const label = document.querySelector(`label[for="xpubRadio${index + 1}"]`);
  if (!label) return;

  // Remove existing status span if any
  const existing = label.querySelector(".verification-status");
  if (existing) existing.remove();

  if (verificationResults.has(xpub)) {
    label.classList.add("cosigner-verified");
    const span = document.createElement("span");
    span.className = "verification-status verified";
    span.textContent = " \u2713";
    label.appendChild(span);
  }
}

function updateProgressIndicator() {
  const container = getElement("xpubRadioContainer");
  let progress = getElement("verificationProgress");
  if (!progress) {
    progress = document.createElement("div");
    progress.id = "verificationProgress";
    container.prepend(progress);
  }

  const total = associatedPathsAndXpubs.length;
  const verified = verificationResults.size;
  progress.textContent = `${verified} of ${total} cosigners verified`;

  if (verified > 0 && verified === total) {
    progress.classList.add("all-verified");
  } else {
    progress.classList.remove("all-verified");
  }
}

function updateReceiptButtonVisibility() {
  const btn = getElement("downloadReceiptButton");
  if (!btn) return;
  btn.style.display = verificationResults.size > 0 ? "inline-flex" : "none";
}

const logSignatureValidationResult = (isValid, errorMessage, verificationData) => {
  const resultElement = getElement("validationResult");

  if (isValid) {
    resultElement.textContent = "Signature is valid!";
    resultElement.classList.add("success");

    if (verificationData && verificationData.xpub) {
      verificationResults.set(verificationData.xpub, verificationData);
      updateRadioLabelStatus(verificationData.xpub);
      updateProgressIndicator();
      updateReceiptButtonVisibility();
    }
  } else {
    resultElement.textContent = errorMessage || "Signature is NOT valid!";
    resultElement.classList.remove("success");
  }
};

function evaluateSignature() {
  const { addressType, relativePath, signatureFormat } = getDerivationSettings();

  const signatureInputValue = getElement("signatureInput").value.trim();
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

    const result = bitcoinUtils.deriveAddress(
      currentXpub,
      relativePath,
      addressType
    );

    if (signatureInputValue.length === 0) {
      throw new Error("Signature is absent");
    }

    const isValid = bitcoinUtils.validateSignature(
      messageInputValue,
      signatureInputValue,
      result.address,
      signatureFormat
    );

    const selectedEntry = associatedPathsAndXpubs.find(
      (entry) => entry.xpub === currentXpub
    );
    const basePath = selectedEntry ? selectedEntry.path : "unknown";
    const fullPath = relativePath
      ? `m${basePath}/${relativePath}`
      : `m${basePath}`;

    logSignatureValidationResult(isValid, null, {
      xpub: currentXpub,
      verified: isValid,
      message: messageInputValue,
      signature: signatureInputValue,
      address: result.address,
      fullPath,
      addressType,
      signatureFormat,
      fingerprint: selectedEntry ? selectedEntry.xpubFingerprint : "unknown",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logSignatureValidationResult(false, error.message);
  }
}

function generateExportText(xpub) {
  const messageInputValue = getElement("messageInput").value || "";
  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === xpub
  );
  const basePath = selectedEntry ? selectedEntry.path : "unknown";
  const { relativePath } = getDerivationSettings();

  const fullPath = relativePath
    ? `m${basePath}/${relativePath}`
    : `m${basePath}`;

  return `${messageInputValue}\n${fullPath}`;
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

function generateSeedsignerQr() {
  if (!selectedXpub) return;

  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === selectedXpub
  );
  const basePath = selectedEntry ? selectedEntry.path : "unknown";
  const { relativePath } = getDerivationSettings();

  const fullPath = relativePath
    ? `m${basePath}/${relativePath}`
    : `m${basePath}`;

  const message = getElement("messageInput").value || "";
  const command = `signmessage: ${fullPath} ascii:${message}`;

  const container = getElement("qrSvgContainer");
  const label = getElement("qrLabel");
  const overlay = getElement("qrOverlay");

  QRCode.toString(command, { type: "svg", width: 300, margin: 2, color: { dark: "#f7931a", light: "#0a0a1a" } })
    .then(function (svgString) {
      container.innerHTML = svgString;
      label.textContent = command;
      overlay.classList.add("visible");
    })
    .catch(function (error) {
      console.error("QR code generation failed:", error);
    });
}

function generateReceipt() {
  const descriptor = getElement("multisigConfigInput").value;
  const quorumMatch = descriptor.match(/sortedmulti\((\d+)/);
  const quorum = quorumMatch ? parseInt(quorumMatch[1]) : "?";
  const total = associatedPathsAndXpubs.length;
  const verified = verificationResults.size;

  const now = new Date();
  const dateStr = now.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");

  let md = `# Gatekeeper Verification Receipt\n\n`;
  md += `**Date:** ${dateStr}\n`;
  md += `**Wallet:** ${quorum}-of-${total} multisig\n`;
  md += `**Cosigners verified:** ${verified} of ${total}\n\n`;
  md += `---\n`;

  associatedPathsAndXpubs.forEach((entry, index) => {
    const fp = entry.xpubFingerprint !== "unknown" ? entry.xpubFingerprint : "N/A";
    md += `\n## Cosigner ${index + 1}: ${fp}\n\n`;

    const result = verificationResults.get(entry.xpub);
    if (result) {
      const shortXpub = `${entry.xpub.slice(0, 10)}...${entry.xpub.slice(-6)}`;
      md += `- **Status:** Verified\n`;
      md += `- **Xpub:** ${shortXpub}\n`;
      md += `- **Fingerprint:** ${result.fingerprint}\n`;
      md += `- **Path:** ${result.fullPath}\n`;
      md += `- **Address:** ${result.address}\n`;
      md += `- **Address type:** ${result.addressType}\n`;
      md += `- **Message:** ${result.message}\n`;
      md += `- **Signature:** ${result.signature}\n`;
      md += `- **Format:** ${result.signatureFormat}\n`;
      md += `- **Timestamp:** ${result.timestamp}\n`;
    } else {
      md += `- **Status:** Not verified\n`;
    }
  });

  md += `\n---\n\n*Verified client-side with [Gatekeeper](https://gatekeeper.dpinkerton.com).*\n`;

  const dateOnly = now.toISOString().slice(0, 10);
  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = `gatekeeper-receipt-${dateOnly}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

module.exports = {
  extractPathsAndXpubsFromMultisigConfig,
  populateXpubRadioLabels,
  extractXpubsAndPopulateRadioButtons,
  importMultisigDescriptor,
  evaluateSignature,
  generateExportText,
  exportToFile,
  generateSeedsignerQr,
  generateReceipt,
};
