const clearValidationStatement = () => {
  const resultElement = document.getElementById("validationResult");
  resultElement.textContent = "";
  resultElement.classList.remove("success");
};

function handleInput(event) {
  const { id } = event.target;
  if (id === "messageInput" || id === "signatureInput") {
    clearValidationStatement();
  }
}

function showCopySuccessNotification() {
  const copyNotification = document.getElementById("copyNotification");
  if (copyNotification) {
    copyNotification.style.display = "inline-block";
    setTimeout(() => {
      copyNotification.style.display = "none";
    }, 2000);
  }
}

module.exports = {
  clearValidationStatement,
  handleInput,
  showCopySuccessNotification,
};
