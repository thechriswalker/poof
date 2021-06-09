function uint8ToBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    bytes = new Uint8Array(bytes);
  }
  const len = bytes.byteLength;
  let binary = "";
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64ToUint8(buf) {
  const binary = atob(buf.replace(/\-/g, "+").replace(/_/g, "/"));
  const len = binary.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function attempt(msg, fn) {
  try {
    return await fn();
  } catch (err) {
    console.warn(err);
    throw Object.assign(new Error(msg), { stack: err.stack });
  }
}

export async function generatePassphrase() {
  const rand = await getRandomData(16);
  return uint8ToBase64(rand);
}

// take a passphrase and turn it into a HASH digest (base64 encoded) and an derivation key
export async function processPassphrase(phrase) {
  // we need to "try/catch" everything to give accurate errors.
  const raw = await attempt("No TextEncoder support", () =>
    new TextEncoder().encode(phrase)
  );
  const subtle = await attempt(
    "No SubtleCrypto support",
    () => window.crypto.subtle
  );
  const digest = await attempt("No digest(SHA-256) support", () =>
    subtle.digest("SHA-256", raw)
  );
  const hash = uint8ToBase64(digest);
  const derivationKey = await attempt(
    "No importKey (raw -> pbkdf2) support",
    () => subtle.importKey("raw", raw, { name: "PBKDF2" }, false, ["deriveKey"])
  );
  return { derivationKey, hash };
}

// encapsulated for feature detection
async function getRandomData(length) {
  const data = await attempt(
    "No Uint8Array support",
    () => new Uint8Array(length)
  );
  await attempt("No crypto.getRandomValues support", () =>
    crypto.getRandomValues(data)
  );
  return data;
}

// create the encryption/decryption key from derivationkey (and specific salt)
async function deriveAESKey(derivationKey, salt, isForEncryption) {
  return await attempt(
    "No deriveKey (PBKDF2/SHA-256 -> AES-GCM-256) support",
    () =>
      crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100e3, hash: "SHA-256" },
        derivationKey,
        { name: "AES-GCM", length: 256 },
        false,
        [isForEncryption ? "encrypt" : "decrypt"]
      )
  );
}

// we encapsulate everything for the encryption here.
export async function encrypt(plain, derivationKey) {
  const salt = await getRandomData(16);
  const iv = await getRandomData(12);
  const key = await deriveAESKey(derivationKey, salt, true);

  // we will have already used a TextEncoder, so we don't need to wrap this.
  const m = new TextEncoder().encode(plain);
  const ct = await attempt("No AES-GCM encrypt support", () =>
    crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, m)
  );
  console.log("encrypt:", { salt, iv, m, ct });
  // we need to send the salt/iv/ct to the server for use in decrypt.
  const ciphertext = [
    uint8ToBase64(salt),
    uint8ToBase64(iv),
    uint8ToBase64(ct),
  ].join(":");

  return ciphertext;
}

// all decrypt functions.
export async function decrypt(ciphertext, derivationKey) {
  const { salt, iv, ct } = await attempt("Ciphertext badly formed", () => {
    const [b64salt, b64iv, b64ct] = ciphertext.split(":");
    return {
      salt: base64ToUint8(b64salt),
      iv: base64ToUint8(b64iv),
      ct: base64ToUint8(b64ct),
    };
  });
  const key = await deriveAESKey(derivationKey, salt, false);
  console.log("decrypt:", { key, salt, iv, ct });
  const m = await attempt("No AES-GCM decrypt support", async () => {
    try {
      return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    } catch (err) {
      console.error(err);
      throw err;
    }
  });
  const plaintext = await attempt("No TextDecoder Support", () =>
    new TextDecoder().decode(m)
  );
  return plaintext;
}

// getElementById helper
// basically you can dereference elements by id.
export const dom = new Proxy(
  {},
  {
    get: (target, prop) => {
      if (typeof prop !== "string") {
        return target[prop];
      }
      const id = prop.replace(/^\$/, ""); // allow dom.$id
      return document.getElementById(id);
    },
  }
);

// just try and do the things. If it fails, that will indicate lack of support...
export async function checkBrowserSupport() {
  try {
    const pass = await generatePassphrase();
    const { derivationKey } = await processPassphrase(pass);
    const msg = "plaintext";
    const cipher = await encrypt(msg, derivationKey);
    const plain = await decrypt(cipher, derivationKey);
    if (msg !== plain) {
      throw new Error("Browser support claimed, but broken");
    }
  } catch (error) {
    console.error(error);
    return { ok: false, error };
  }
  return { ok: true, error: null };
}
