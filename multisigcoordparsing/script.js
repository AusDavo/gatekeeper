function extractPaths() {
    // Get the input text
    const inputText = document.getElementById('inputText').value.trim();

    // Check if inputText is empty
    if (!inputText) {
        alert('Please enter some text.');
        return;
    }

    // Clear previous results
    const addressList = document.getElementById('addressList');
    addressList.innerHTML = '';

    // Extract Bitcoin address derivation paths and xpubs from the input text
    const { xpubs, pathsDictionary } = extractXpubsAndPaths(inputText);

    // Display tidied paths in the list
    xpubs.forEach(xpub => {
        const listItem = document.createElement('li');
        const paths = pathsDictionary[xpub] || 'not apparent';
        listItem.textContent = `${xpub}: ${paths}`;
        addressList.appendChild(listItem);
    });
}

function extractXpubsAndPaths(inputText) {
    const xpubs = [];
    const pathsDictionary = {};

    // Define a regular expression to match xpubs
    const xpubRegex = /\b\w*xpub\w*\b/g;

    // Find all matches in the input text
    const xpubMatches = inputText.match(xpubRegex) || [];

    // Iterate over xpub matches
    xpubMatches.forEach(xpub => {
        // Find the index of the current xpub in the input text
        const xpubIndex = inputText.indexOf(xpub);

        // Extract the substring from the beginning to the current xpub
        const substringBeforeXpub = inputText.substring(0, xpubIndex);

        // Extract derivation paths from the substring before the xpub
        const paths = extractDerivationPaths(substringBeforeXpub);

        // Store xpub and associated paths in the dictionary
        xpubs.push(xpub);
        pathsDictionary[xpub] = paths;
    });

    return { xpubs, pathsDictionary };
}

// The rest of your code remains unchanged...
















