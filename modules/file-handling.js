const multisigOperations = require("./multisig-operations");

function handleFileUpload(event) {
  const file = event.target.files[0];

  if (file) {
    const reader = new FileReader();

    reader.onload = function (e) {
      const fileContent = e.target.result;

      document.getElementById("multisigConfigInput").value = fileContent;
      multisigOperations.extractXpubsAndPopulateRadioButtons();
    };

    reader.readAsText(file);
  } else {
    console.error("No file selected");
  }
}

module.exports = { handleFileUpload };
