const uiInteraction = require("./ui-interaction");
const fileHandling = require("./file-handling");
const multisigOperations = require("./multisig-operations");
const QRCode = require("qrcode");

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

  document.getElementById("qrOverlay").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) {
      event.currentTarget.classList.remove("visible");
    }
  });

  document.getElementById("seedsignerInfoToggle").addEventListener("click", () => {
    document.getElementById("seedsignerInfo").classList.toggle("visible");
  });

  const donationAddress = document.getElementById("donationLink").textContent.trim();
  QRCode.toString(donationAddress, { type: "svg", margin: 2 })
    .then(function (svg) {
      document.getElementById("donationQr").innerHTML = svg;
    })
    .catch(function (err) {
      console.error("Donation QR generation failed:", err);
    });
};

module.exports = { addEventListeners };
