const uiInteraction = require("./ui-interaction");
const fileHandling = require("./file-handling");
const multisigOperations = require("./multisig-operations");

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
    // Add more cases as needed
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
  ];

  buttonIds.forEach((buttonId) => {
    document.getElementById(buttonId).addEventListener("click", () => {
      handleButtonClick(buttonId);
    });
  });
};

module.exports = { addEventListeners };
