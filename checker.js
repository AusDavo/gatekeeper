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
