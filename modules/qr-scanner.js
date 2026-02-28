const { Html5Qrcode } = require("html5-qrcode");

let html5QrCode = null;

function startScanning(elementId, onResult) {
  const container = document.getElementById("qrReaderContainer");
  container.classList.add("visible");

  html5QrCode = new Html5Qrcode(elementId);

  html5QrCode
    .start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (decodedText) => {
        stopScanning();
        onResult(decodedText);
      },
      () => {}
    )
    .catch((err) => {
      console.error("QR scanner failed to start:", err);
      stopScanning();
    });
}

function stopScanning() {
  const container = document.getElementById("qrReaderContainer");
  container.classList.remove("visible");

  if (html5QrCode) {
    html5QrCode
      .stop()
      .then(() => {
        html5QrCode.clear();
        html5QrCode = null;
      })
      .catch(() => {
        html5QrCode = null;
      });
  }
}

module.exports = { startScanning, stopScanning };
