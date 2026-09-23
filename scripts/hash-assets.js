// Stamps index.html's local script and stylesheet URLs with a content hash
// (e.g. bundled.js?h=2c794208), so browsers fetch a fresh copy whenever the file
// changes and keep using their cache while it doesn't.
//
// Runs as the last step of `npm run build`. Re-running is safe: an existing
// ?h= is replaced, and an unchanged file keeps the same hash.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const HTML = path.join(ROOT, "index.html");
const ASSETS = ["theme-init.js", "icons.css", "style.css", "bundled.js"];

const hashOf = (file) =>
  crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, file)))
    .digest("hex")
    .slice(0, 8);

let html = fs.readFileSync(HTML, "utf8");

for (const asset of ASSETS) {
  const escaped = asset.replace(/\./g, "\\.");
  const pattern = new RegExp(`((?:src|href)=")${escaped}(?:\\?h=[0-9a-f]+)?"`, "g");
  const matches = html.match(pattern);
  if (!matches || matches.length !== 1) {
    throw new Error(
      `Expected exactly one reference to ${asset} in index.html, found ${matches ? matches.length : 0}.`,
    );
  }
  const hash = hashOf(asset);
  html = html.replace(pattern, `$1${asset}?h=${hash}"`);
  console.log(`${asset}?h=${hash}`);
}

fs.writeFileSync(HTML, html);
