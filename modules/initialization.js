const initialize = () => {
  clearInputValues();
};

function clearInputValues() {
  multisigConfigInput.value = "";
  messageInput.value = "";
  signatureInput.value = "";
}

module.exports = { initialize };
