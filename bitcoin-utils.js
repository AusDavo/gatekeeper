// bitcoin-utils.js
const ecc = require("@bitcoinerlab/secp256k1");
const { BIP32Factory } = require("bip32");
const bitcoin = require("bitcoinjs-lib");
const bitcoinMessage = require("bitcoinjs-message");
const { Verifier } = require("bip322-js");

// Initialize BIP32 with the secp256k1 library
const bip32 = BIP32Factory(ecc);

const ADDRESS_TYPES = {
  legacy: "legacy", // P2PKH - starts with 1
  segwit: "segwit", // P2WPKH - starts with bc1q
  taproot: "taproot", // P2TR - starts with bc1p
};

const SIGNATURE_FORMATS = {
  electrum: "electrum", // Standard/Electrum format (ECDSA)
  bip137: "bip137", // BIP-137 (Trezor) format (ECDSA with address type header)
  bip322: "bip322", // BIP-322 (Simple) format (works with all address types)
};

/**
 * Detects the address type from a Bitcoin address string.
 */
function detectAddressType(address) {
  if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
    return ADDRESS_TYPES.taproot;
  } else if (address.startsWith("bc1q") || address.startsWith("tb1q")) {
    return ADDRESS_TYPES.segwit;
  } else if (address.startsWith("3") || address.startsWith("2")) {
    return "segwit-wrapped"; // P2SH-P2WPKH
  } else {
    return ADDRESS_TYPES.legacy; // P2PKH (starts with 1 or m/n for testnet)
  }
}

/**
 * Derives a child node from an xpub using a relative path.
 * Only non-hardened derivation is possible from an xpub.
 */
function deriveFromPath(xpub, relativePath) {
  const node = bip32.fromBase58(xpub);

  if (!relativePath || relativePath === "") {
    return node;
  }

  const segments = relativePath.split("/").filter((s) => s !== "");

  let derived = node;
  for (const segment of segments) {
    if (segment.includes("'") || segment.includes("h")) {
      throw new Error(
        "Hardened derivation not possible from xpub. Use only non-hardened indices."
      );
    }

    const index = parseInt(segment, 10);
    if (isNaN(index) || index < 0 || index > 2147483647) {
      throw new Error(`Invalid path segment: ${segment}`);
    }

    derived = derived.derive(index);
  }

  return derived;
}

/**
 * Converts a 33-byte public key to x-only (32-byte) format for Taproot.
 */
function toXOnly(pubkey) {
  return pubkey.subarray(1, 33);
}

/**
 * Derives an address from an xpub at a given relative path.
 */
function deriveAddress(xpub, relativePath, addressType = ADDRESS_TYPES.legacy) {
  const derived = deriveFromPath(xpub, relativePath);
  const publicKey = derived.publicKey;

  let payment;
  switch (addressType) {
    case ADDRESS_TYPES.taproot:
      payment = bitcoin.payments.p2tr({
        internalPubkey: toXOnly(publicKey),
      });
      break;
    case ADDRESS_TYPES.segwit:
      payment = bitcoin.payments.p2wpkh({ pubkey: publicKey });
      break;
    case ADDRESS_TYPES.legacy:
    default:
      payment = bitcoin.payments.p2pkh({ pubkey: publicKey });
      break;
  }

  return {
    address: payment.address,
    publicKey: publicKey.toString("hex"),
  };
}

/**
 * Validates a Bitcoin signed message using the specified format.
 *
 * - Electrum/BIP-137: Use bitcoinjs-message for legacy, bip322-js for segwit
 * - BIP-322: Use bip322-js for all address types
 */
function validateSignature(message, signature, address, signatureFormat) {
  const detectedType = detectAddressType(address);

  // BIP-322 format - use bip322-js for all address types
  if (signatureFormat === SIGNATURE_FORMATS.bip322) {
    return Verifier.verifySignature(address, message, signature);
  }

  // For legacy addresses, use bitcoinjs-message
  if (detectedType === ADDRESS_TYPES.legacy) {
    try {
      return bitcoinMessage.verify(message, address, signature);
    } catch (error) {
      throw new Error(`Legacy verification failed: ${error.message}`);
    }
  }

  // For SegWit and wrapped SegWit, use bip322-js
  // BIP-137 uses strict mode, Electrum uses loose mode
  const strictMode = signatureFormat === SIGNATURE_FORMATS.bip137;
  return Verifier.verifySignature(address, message, signature, strictMode);
}

/**
 * Returns information about signature format compatibility with address types.
 */
function getFormatCompatibility(signatureFormat, addressType) {
  // BIP-322 works with everything
  if (signatureFormat === SIGNATURE_FORMATS.bip322) {
    return { compatible: true, note: null };
  }

  // Electrum and BIP-137 don't work with Taproot (requires Schnorr)
  if (addressType === ADDRESS_TYPES.taproot) {
    return {
      compatible: false,
      note: "Taproot addresses require BIP-322 format for signature verification.",
    };
  }

  return { compatible: true, note: null };
}

module.exports = {
  deriveAddress,
  deriveFromPath,
  validateSignature,
  getFormatCompatibility,
  detectAddressType,
  ADDRESS_TYPES,
  SIGNATURE_FORMATS,
  toXOnly,
};
