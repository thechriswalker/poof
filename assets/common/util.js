export function uint8ToBase64(bytes) {
  const len = bytes.byteLength;
  let binary = "";
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function base64ToUint8(buf) {
  const binary = atob(buf.replace(/\-/g, "+").replace(/_/g, "/"));
  const len = binary.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function supportsEnoughCrypto() {
  // where we have modules we should also have crypto.
  // Except Edge support is dodgy.
  // also not quite all module supporting browsers support TextEncoder/Decoder.
  const hasSubtle = "crypto" in window && "subtle" in window.crypto;
  const hasTextCodec = "TextEncoder" in window && "TextDecoder" in window;

  // we need a number of crypto operations, and algorithm support can be mixed.
  const hasAlgoSupport = await (async function () {
    const data = new Uint8Array(8);
    try {
      // digest SHA-256
      await crypto.subtle.digest("SHA-256", data);
      // importKey from RAW to PBKDF2 for deriving
      const k = await crypto.subtle.importKey(
        "raw",
        data,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      // deriveKey from PBKDF2 to AES-GCM fro encrypt or decrypt
      await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: data, iterations: 100000, hash: "SHA-256" },
        k,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt", "encrypt"]
      );
      // we will assume (ha ha) that if it let's us create a key for enc/dec AES-GCM then
      // it supports those operations.
    } catch (err) {
      console.error("unsupported:", err);
      return false;
    }
    return true;
  })();

  return hasSubtle && hasTextCodec && hasAlgoSupport;
}
