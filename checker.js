function loadConfiguration() {
    // Clear the xpubs dropdown list
    document.getElementById("xpubs").innerHTML = "";

    // Extract all the xpub keys from the descriptor element's value
    const xpubs = [...document.getElementById("descriptor").value.matchAll(/\b\w*xpub\w*\b/g)];

    // Get the select element
    const select = document.getElementById("xpubs");

    // Add a new Option element for each xpub key found
    xpubs.forEach(xpub => select.add(new Option(xpub)));
}

function getPublicKeyFromDerivationPath(xpub, path) {
    const publicKey = bip32.fromBase58(xpub).derivePath(path).publicKey;
    return publicKey;
  }

function calculatePublicKey() {
  // Get the selected xpub key from the dropdown list
  const xpub = document.getElementById("xpubs").value;

  // Get the derivation path from the input field
  const path = document.getElementById("path").value;

  // Call the getPublicKeyFromDerivationPath function to obtain the public key
  const publicKey = getPublicKeyFromDerivationPath(xpub, path);

  // Display the public key on the page
  document.getElementById("public-key").innerHTML = publicKey;
}