function extractPathsAndXpubsFromMultisigConfig(multisigConfig) {
    const pathsRegex = /\/[\dh'\/]+(?:[h'](?=\d)|[h'])/g;
    const xpubsRegex = /\b\w*xpub\w*\b/g;

    const extractMatches = (regex) => [...multisigConfig.matchAll(regex)].map(match => match[0]);

    const associatedPathsAndXpubs = () => {
        const xpubs = extractMatches(xpubsRegex);
        const parts = multisigConfig.split(/\b\w*xpub\w*\b/);

        return xpubs.map((xpub, index) => ({
            path: (parts[index].match(pathsRegex) || ['unknown'])[0],
            xpub,
        }));
    };

    return associatedPathsAndXpubs();
}

// Example usage:
const multisigConfig = "BSMS 1.0 wsh(sortedmulti(2,[d2060b25 m/48'/0'/0'/2h ]xpub6EgnSzhMJxPcHJKTM8UW3yR5A4gQBtDfRMy89qV9U99hpCmr7EBSbn2py9W3b6ZQjznxocDThg7QogD1itv1SbWYUKkeYizbFB1H5isEoJu,[b58bd39f/48h/0h/0h/2h]xpub6EBVpdpMMhzyvZLQeDvS4ChXqeJHNRUsMRrRmHKSZKoqxiEiwaEYGuYRvqJGzuKXXXK5bmtPdcDdUxNgnKuLD4xMqEihPtDaedNijaUdvAo,[ddac3619/48h/0h/0h/2h]xpub6DzrNuhmcXd397JyaQ9yHzCENNtqYxDJtaU8zd3ok7Qz5vfAk1ZjpfT5W3qkHKGFX7PYt9sf7tS7yMBaMwyBBtBA9mB2quYcwR8nUqrpeaT))/0/*,/1/*bc1qgdn6r06nknx3gaqnd67ygn748v894dpw79qrggqp34y2j6dhqfyqghg7h8# Exported from Nunchuk Name: Noosa testing Policy: 1 of 3 Format: P2WSH Derivation: m/48'/0'/0'/2'0e589c39:xpub6ETbkTdCWxhFmizpXGQ8U7Lx7kKQ8CnnRNps96Q8Z4XX7JAAEvCHeJv5UM5kU1Cm3kJUgr5PeQkFqUrXAfetxD1skJ7jie7qMVm7BMdJe36Derivation: m/48'/0'/0'/2'46b5d9e5:xpub6FQywvvaYNWevawA3PkVMa7mmpP17zPkzKew18NZvQqjw9Q2ixyKwzoowVVgmmrHveDEwioLSRf6kvSEmjLqpgQY44pki8iKU6wXKeHBLKcDerivation: m/48'/0'/2'/2'1756fb36:xpub6EsDuBZNA3gQUFHh5WXoF1PNx7HEAyY9HEPAa5Qid4TRBXomAdqfL1XmEiLFbTc4hAVu7JWA5iQ5YKmbgvK1sSpmazSpqZPogz84ArEtSuU";
const result = extractPathsAndXpubsFromMultisigConfig(multisigConfig);
console.log(result);
