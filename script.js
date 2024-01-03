let associatedPathsAndXpubs;

function clearValidationStatement() {
  document.getElementById("validationResult").textContent = "";
}

document
  .getElementById("extractXpubsButton")
  .addEventListener("click", extractXpubsAndPopulateDropdown);
document
  .getElementById("importDescriptorButton")
  .addEventListener("click", importMultisigDescriptor);
document
  .getElementById("xpubDropdown")
  .addEventListener("change", clearValidationStatement);
document
  .getElementById("messageInput")
  .addEventListener("input", clearValidationStatement);
document
  .getElementById("signatureInput")
  .addEventListener("input", clearValidationStatement);
document
  .getElementById("evaluateSignatureButton")
  .addEventListener("click", evaluateSignature);
