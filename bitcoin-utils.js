// bitcoin-utils.js
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const bitcoin = require("bitcoinjs-lib");
const bitcoinMessage = require("bitcoinjs-message");

// Initialize BIP32 with the secp256k1 library
const bip32 = BIP32Factory(ecc);

const ADDRESS_TYPES = {
  legacy: "legacy", // P2PKH - starts with 1
  segwit: "segwit", // P2WPKH - starts with bc1q
  taproot: "taproot", // P2TR - starts with bc1p
};

/**
 * Derives a child node from an xpub using a relative path.
 * Only non-hardened derivation is possible from an xpub.
 * @param {string} xpub - The extended public key
 * @param {string} relativePath - Path like "0/0" or "1/5" (no leading slash)
 * @returns {object} - The derived BIP32 node
 */
function deriveFromPath(xpub, relativePath) {
  const node = bip32.fromBase58(xpub);

  if (!relativePath || relativePath === "") {
    return node;
  }

  // Parse and validate path segments
  const segments = relativePath.split("/").filter((s) => s !== "");

  let derived = node;
  for (const segment of segments) {
    // Check for hardened derivation attempt (not possible from xpub)
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
 * @param {Buffer} pubkey - 33-byte compressed public key
 * @returns {Buffer} - 32-byte x-only public key
 */
function toXOnly(pubkey) {
  return pubkey.subarray(1, 33);
}

/**
 * Derives an address from an xpub at a given relative path.
 * @param {string} xpub - The extended public key
 * @param {string} relativePath - Relative derivation path (e.g., "0/0")
 * @param {string} addressType - One of: legacy, segwit, taproot
 * @returns {object} - { address, publicKey }
 */
function deriveAddress(xpub, relativePath, addressType = ADDRESS_TYPES.legacy) {
  const derived = deriveFromPath(xpub, relativePath);
  const publicKey = derived.publicKey;

  let payment;
  switch (addressType) {
    case ADDRESS_TYPES.taproot:
      // Taproot requires x-only public key (32 bytes)
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
 * Decodes a base64url-encoded signature to a Buffer.
 */
function base64UrlDecode(base64Url) {
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64");
}

/**
 * Validates a Bitcoin signed message.
 * Note: Standard message signing works with Legacy and SegWit addresses.
 * Taproot uses Schnorr signatures which require different verification (BIP-322).
 *
 * @param {string} message - The original message
 * @param {string} signature - Base64-encoded signature
 * @param {string} address - The Bitcoin address
 * @param {string} addressType - The address type for context
 * @returns {boolean} - True if signature is valid
 */
function validateSignature(message, signature, address, addressType) {
  // Taproot addresses use Schnorr signatures (BIP-340) and BIP-322 message format
  // Standard bitcoinjs-message doesn't support this natively
  if (addressType === ADDRESS_TYPES.taproot) {
    throw new Error(
      "Taproot signature verification requires BIP-322. Use Legacy or SegWit for message signing."
    );
  }

  const decodedSignature = base64UrlDecode(signature);
  return bitcoinMessage.verify(message, address, decodedSignature);
}

module.exports = {
  deriveAddress,
  deriveFromPath,
  base64UrlDecode,
  validateSignature,
  ADDRESS_TYPES,
  toXOnly,
};
