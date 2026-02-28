const uiInteraction = require("./ui-interaction");
const fileHandling = require("./file-handling");
const multisigOperations = require("./multisig-operations");
const qrScanner = require("./qr-scanner");
const bitcoinUtils = require("../bitcoin-utils");
const QRCode = require("qrcode");

let activeScanTarget = null;

const handleButtonClick = (buttonId) => {
  switch (buttonId) {
    case "extractXpubsButton":
      multisigOperations.extractXpubsAndPopulateRadioButtons();
      break;
    case "importDescriptorButton":
      multisigOperations.importMultisigDescriptor();
      break;
    case "evaluateSignatureButton":
      multisigOperations.evaluateSignature();
      break;
    case "exportButton":
      multisigOperations.exportToFile();
      break;
    case "seedsignerQrButton":
      multisigOperations.generateSeedsignerQr();
      break;
  }
};

const addEventListeners = () => {
  document.body.addEventListener("input", uiInteraction.handleInput);

  document
    .getElementById("fileInput")
    .addEventListener("change", fileHandling.handleFileUpload);

  const buttonIds = [
    "extractXpubsButton",
    "importDescriptorButton",
    "evaluateSignatureButton",
    "exportButton",
    "seedsignerQrButton",
  ];

  buttonIds.forEach((buttonId) => {
    document.getElementById(buttonId).addEventListener("click", () => {
      handleButtonClick(buttonId);
    });
  });

  // QR overlay click-to-close
  document.getElementById("qrOverlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) {
      event.currentTarget.classList.remove("visible");
    }
  });

  // ESC key closes overlays and scanner
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      document.getElementById("qrOverlay").classList.remove("visible");
      qrScanner.stopScanning();
    }
  });

  // SeedSigner info toggle
  document.getElementById("seedsignerInfoToggle").addEventListener("click", () => {
    document.getElementById("seedsignerInfo").classList.toggle("visible");
  });

  // Descriptor QR scan
  document.getElementById("scanDescriptorQrButton").addEventListener("click", () => {
    activeScanTarget = "descriptor";
    qrScanner.startScanning("qr-reader", handleScanResult);
  });

  // Signature QR scan
  document.getElementById("scanSignatureQrButton").addEventListener("click", () => {
    activeScanTarget = "signature";
    qrScanner.startScanning("qr-reader", handleScanResult);
  });

  // QR scanner close button
  document.getElementById("qrScannerClose").addEventListener("click", () => {
    qrScanner.stopScanning();
  });

  // Signature file upload
  document.getElementById("uploadSignatureButton").addEventListener("click", () => {
    document.getElementById("signatureFileInput").click();
  });

  document
    .getElementById("signatureFileInput")
    .addEventListener("change", fileHandling.handleSignatureFileUpload);

  // Drag-and-drop for descriptor
  const uploadContainer = document.getElementById("uploadContainer");

  uploadContainer.addEventListener("dragover", (event) => {
    event.preventDefault();
    uploadContainer.classList.add("dragover");
  });

  uploadContainer.addEventListener("dragleave", () => {
    uploadContainer.classList.remove("dragover");
  });

  uploadContainer.addEventListener("drop", fileHandling.handleDescriptorDrop);

  // Donation QR generation
  const donationAddress = document.getElementById("donationLink").textContent.trim();
  QRCode.toString(donationAddress, { type: "svg", margin: 2 })
    .then(function (svg) {
      document.getElementById("donationQr").innerHTML = svg;
    })
    .catch(function (err) {
      console.error("Donation QR generation failed:", err);
    });
};

function handleScanResult(decodedText) {
  if (activeScanTarget === "descriptor") {
    document.getElementById("multisigConfigInput").value = decodedText;
    multisigOperations.extractXpubsAndPopulateRadioButtons();
  } else if (activeScanTarget === "signature") {
    document.getElementById("signatureInput").value = decodedText;
    bitcoinUtils.showDetectedFormat(decodedText);
  }
  activeScanTarget = null;
}

module.exports = { addEventListeners };
