const bitcoinUtils = require("./bitcoin-utils");

const associatedPathsAndXpubs = [];
let selectedXpub = null;

function clearValidationStatement() {
  document.getElementById("validationResult").textContent = "";
}

document.body.addEventListener("input", function (event) {
  if (
    event.target.id === "messageInput" ||
    event.target.id === "signatureInput"
  ) {
    clearValidationStatement();
  }
});

const fileInput = document.getElementById("fileInput");

fileInput.addEventListener("change", handleFileUpload);

function handleFileUpload(event) {
  const file = event.target.files[0];

  if (file) {
    const reader = new FileReader();

    reader.onload = function (e) {
      const fileContent = e.target.result;

      // Populate the multisigConfigInput with the content of the file
      document.getElementById("multisigConfigInput").value = fileContent;

      // Trigger the logic as if the "Extract XPUBs" button was clicked
      extractXpubsAndPopulateRadioButtons();
    };

    reader.readAsText(file);
  } else {
    console.error("No file selected");
  }
}

document
  .getElementById("extractXpubsButton")
  .addEventListener("click", function () {
    extractXpubsAndPopulateRadioButtons(associatedPathsAndXpubs);
  });
document
  .getElementById("importDescriptorButton")
  .addEventListener("click", importMultisigDescriptor);
document
  .getElementById("evaluateSignatureButton")
  .addEventListener("click", function () {
    evaluateSignature(selectedXpub);
  });

function logSignatureValidationResult(isValid, errorMessage) {
  const resultElement = document.getElementById("validationResult");

  if (isValid) {
    resultElement.textContent = "Signature is valid!";
  } else {
    resultElement.textContent = errorMessage || "Signature is NOT valid!";
  }
}

function extractPathsAndXpubsFromMultisigConfig(multisigConfig) {
  const pathsRegex = /\/[\dh'\/]+(?:[h'](?=\d)|[h'])/g;
  const xpubsRegex = /\b\w*xpub\w*\b/g;
  const xpubFingerprintRegex = /\b[A-Fa-f0-9]{8}\b/g;

  const extractMatches = (regex) =>
    [...multisigConfig.matchAll(regex)].map((match) => match[0]);

  const formatPath = (path) =>
    (path.match(pathsRegex) || ["unknown"])[0].replace(/h/g, "'");

  return extractMatches(xpubsRegex).map((xpub, index) => {
    const xpubFingerprints = extractMatches(xpubFingerprintRegex);
    const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

    return {
      path: formatPath(parts[index]),
      xpub,
      xpubFingerprint: xpubFingerprints[index] || "unknown",
    };
  });
}

function populateXpubRadioLabels(xpubsAndFingerprints, container) {
  container.innerHTML = ""; // Clear existing options

  xpubsAndFingerprints.forEach((entry, index) => {
    const { xpub, xpubFingerprint } = entry;

    const radioBtn = document.createElement("input");
    radioBtn.type = "radio";
    radioBtn.name = "xpubRadio";
    radioBtn.value = xpub;
    radioBtn.id = `xpubRadio${index + 1}`;

    const label = document.createElement("label");
    label.htmlFor = `xpubRadio${index + 1}`;

    const shortXpub = `${xpub.slice(0, 10)}...${xpub.slice(-6)}`;
    const fingerprintFormatted =
      xpubFingerprint !== "unknown" ? ` (fingerprint: ${xpubFingerprint})` : "";

    label.textContent = `${shortXpub}${fingerprintFormatted}`;

    container.appendChild(radioBtn);
    container.appendChild(label);

    container.appendChild(document.createElement("br"));
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
  // Get reference to xpubRadioContainer
  const xpubRadioContainer = document.getElementById("xpubRadioContainer");
};

function showCopySuccessNotification() {
  const copyNotification = document.getElementById("copyNotification");
  if (copyNotification) {
    copyNotification.style.display = "inline-block";
    setTimeout(() => {
      copyNotification.style.display = "none";
    }, 2000); // Hide the notification after 2 seconds
  }
}

function generateExportText(selectedXpub) {
  const messageInputValue = document.getElementById("messageInput").value || "";
  const selectedEntry = associatedPathsAndXpubs.find(
    (entry) => entry.xpub === selectedXpub
  );
  const formattedPath = selectedEntry ? selectedEntry.path : "unknown";

  return `${messageInputValue}\nm${formattedPath}/0`;
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

function extractXpubsAndPopulateRadioButtons() {
  const getElement = (id) => document.getElementById(id);
  const hideElement = (element) => (element.style.display = "none");
  const showElement = (element, displayType = "inline-block") =>
    (element.style.display = displayType);

  // Get reference to xpubRadioContainer
  const xpubRadioContainer = getElement("xpubRadioContainer");

  const {
    multisigSection,
    importDescriptorButton,
    elementsBelowXpub,
    derivationPathResult,
    messageInput,
    signatureInput,
    evaluateSignatureButton,
    copyButton,
  } = {
    multisigSection: getElement("multisigSection"),
    importDescriptorButton: getElement("importDescriptorButton"),
    elementsBelowXpub: getElement("elementsBelowXpub"),
    derivationPathResult: getElement("derivationPathResult"),
    messageInput: getElement("messageInput"),
    signatureInput: getElement("signatureInput"),
    evaluateSignatureButton: getElement("evaluateSignatureButton"),
    copyButton: getElement("copyButton"),
  };

  try {
    associatedPathsAndXpubs.length = 0; // Clear the existing array
    associatedPathsAndXpubs.push(
      ...extractPathsAndXpubsFromMultisigConfig(multisigConfigInput.value)
    );

    showElement(importDescriptorButton, "inline-block");

    // Dynamically create and populate radio buttons
    associatedPathsAndXpubs.forEach((entry, index) => {
      const radioBtn = document.createElement("input");
      radioBtn.type = "radio";
      radioBtn.name = "xpubRadio";
      radioBtn.value = entry.xpub;
      radioBtn.id = `xpubRadio${index + 1}`;
      const label = document.createElement("label");
      label.htmlFor = `xpubRadio${index + 1}`;
      label.innerText = `XPub ${index + 1}`;

      xpubRadioContainer.appendChild(radioBtn);
      xpubRadioContainer.appendChild(label);

      xpubRadioContainer.appendChild(document.createElement("br"));

      showElement(xpubRadioContainer, "inline-block");

      xpubRadioContainer.addEventListener("change", function (event) {
        selectedXpub = event.target.value;
        if (selectedXpub) {
          const selectedEntry = associatedPathsAndXpubs.find(
            (entry) => entry.xpub === selectedXpub
          );
          const formattedPath = selectedEntry ? selectedEntry.path : "unknown";

          const selectedAddress = bitcoinUtils.deriveAddress(
            selectedXpub,
            0
          ).address;
          derivationPathResult.innerHTML = `
  The first child key of the selected xpub affords the following address:<br>
  <strong>${selectedAddress}</strong><br>
  Your collaborator can derive its corresponding private key from the BIP32 root key using this path:<br>
  <strong>m${formattedPath}/0</strong><br>
  Ask your collaborator to sign a new message using this key. Paste the returned signature below and click the button to evaluate it. A successful outcome indicates that your collaborator maintains control over their key.
`;

          showElement(elementsBelowXpub);
          showElement(messageInput, "inline-block");
          showElement(signatureInput, "inline-block");
          showElement(evaluateSignatureButton, "inline-block");
          showElement(copyButton, "inline-block");

          copyButton.addEventListener("click", async function () {
            const textToCopy = generateExportText(selectedXpub);

            try {
              await navigator.clipboard.writeText(textToCopy);
              console.log("Text successfully copied to clipboard");
              showCopySuccessNotification(); // Display copy success notification
            } catch (err) {
              console.error("Unable to copy to clipboard", err);
            }
          });

          // Clear the validation result when a new selection is made
          clearValidationStatement();
        }
      });
    });

    // Use the function to populate radio buttons and labels
    populateXpubRadioLabels(associatedPathsAndXpubs, xpubRadioContainer);
  } catch (error) {
    console.error("Error during xpub extraction:", error.message);
  }
  // Hide unnecessary elements after extracting XPubs
  hideElement(multisigSection);
}

function importMultisigDescriptor() {
  const getById = (id) => document.getElementById(id);
  const show = (element, displayType = "inline-block") =>
    (element.style.display = displayType);
  const hide = (element) => (element.style.display = "none");

  const {
    multisigSection,
    extractXpubsButton,
    elementsBelowXpub,
    xpubRadioContainer,
    importDescriptorButton,
  } = {
    multisigSection: getById("multisigSection"),
    extractXpubsButton: getById("extractXpubsButton"),
    elementsBelowXpub: getById("elementsBelowXpub"),
    xpubRadioContainer: getById("xpubRadioContainer"),
    importDescriptorButton: getById("importDescriptorButton"),
  };

  // Show the original input, button, and label
  [multisigSection, extractXpubsButton].forEach((element) => show(element));

  // Hide the elements below xpub and the "Select xpub" dropdown when importing
  [elementsBelowXpub, xpubRadioContainer, importDescriptorButton].forEach(hide);

  // Clear the existing input value
  multisigConfigInput.value = "";

  // Optionally, you can reset or hide other related elements as needed
}

function evaluateSignature() {
  // Declare selectedXpub with a default value
  let selectedXpub = null;

  const getAddressFromXpub = (xpub) =>
    bitcoinUtils.deriveAddress(xpub, 0).address;

  const signatureInputValue = document.getElementById("signatureInput").value;
  const messageInputValue =
    document.getElementById("messageInput").value || "default";

  // Find the selected radio button
  const selectedRadio = document.querySelector(
    'input[name="xpubRadio"]:checked'
  );

  try {
    if (selectedRadio) {
      // Extract the index from the radio button's id
      const index = parseInt(selectedRadio.id.replace("xpubRadio", "")) - 1;

      // Use the index to get the associated xpub from the stored array
      selectedXpub = associatedPathsAndXpubs[index].xpub;
    } else {
      throw new Error("No xpub selected");
    }

    const address = getAddressFromXpub(selectedXpub);

    // Check if the signature is malformed or absent
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

    // Log the validation result with error message
    logSignatureValidationResult(isValid);
  } catch (error) {
    if (
      error.message === "Invalid signature length" ||
      error.message === "Signature is absent"
    ) {
      // Provide user-friendly feedback for invalid signatures
      logSignatureValidationResult(false, error.message);
    } else {
      // Handle other errors
      logSignatureValidationResult(false, "An unexpected error occurred.");
    }
  }
}

// Add an event listener to the "Evaluate Signature" button
document
  .getElementById("evaluateSignatureButton")
  .addEventListener("click", evaluateSignature);

document
  .getElementById("importDescriptorButton")
  .addEventListener("click", importMultisigDescriptor);

document.getElementById("exportButton").addEventListener("click", exportToFile);
