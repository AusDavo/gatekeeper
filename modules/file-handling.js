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

function handleDescriptorDrop(event) {
  event.preventDefault();
  event.stopPropagation();

  const container = document.getElementById("uploadContainer");
  container.classList.remove("dragover");

  const file = event.dataTransfer.files[0];
  if (!file) return;

  const ext = file.name.toLowerCase().split(".").pop();
  if (ext !== "txt" && ext !== "bsms") return;

  const reader = new FileReader();
  reader.onload = function (e) {
    document.getElementById("multisigConfigInput").value = e.target.result;
    multisigOperations.extractXpubsAndPopulateRadioButtons();
  };
  reader.readAsText(file);
}

function parseColdcardSignedFile(text) {
  const lines = text.split("\n").map((l) => l.trim());

  const sigHeaderIdx = lines.findIndex(
    (l) => l === "-----BEGIN BITCOIN SIGNED MESSAGE-----"
  );
  const sigMiddleIdx = lines.findIndex(
    (l) => l === "-----BEGIN SIGNATURE-----"
  );
  const sigEndIdx = lines.findIndex(
    (l) => l === "-----END BITCOIN SIGNED MESSAGE-----"
  );

  if (sigHeaderIdx === -1 || sigMiddleIdx === -1 || sigEndIdx === -1) {
    return null;
  }

  const signatureLines = lines.slice(sigMiddleIdx + 1, sigEndIdx);
  // Coldcard format: first line after BEGIN SIGNATURE is the address, second is the signature
  const sig = signatureLines.length >= 2 ? signatureLines[1] : signatureLines[0];

  if (!sig || sig.length === 0) return null;

  return { signature: sig, format: "bip137" };
}

function handleSignatureFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const text = e.target.result;

    // Try Coldcard ASCII-armored format first
    const coldcard = parseColdcardSignedFile(text);
    if (coldcard) {
      document.getElementById("signatureInput").value = coldcard.signature;
      document.getElementById("signatureFormatSelect").value = coldcard.format;

      const bitcoinUtils = require("../bitcoin-utils");
      bitcoinUtils.showDetectedFormat(coldcard.signature);
      return;
    }

    // Otherwise treat as raw base64 signature text
    const trimmed = text.trim();
    document.getElementById("signatureInput").value = trimmed;

    const bitcoinUtils = require("../bitcoin-utils");
    bitcoinUtils.showDetectedFormat(trimmed);
  };
  reader.readAsText(file);
}

module.exports = {
  handleFileUpload,
  handleDescriptorDrop,
  handleSignatureFileUpload,
  parseColdcardSignedFile,
};
