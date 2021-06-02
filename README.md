# poof! magically disappearing secret sharing

Lots of prior work in this field (citation required), but I figured I could have a go and see about leveraging the new `WebCrypto` APIs.

`poof` allows you to securely share secrets in a self-destructing, time-limited, passphrase protected way.

- The server never sees the secret, or the passphrase.
- The server only ever releases the encrypted secret once, within the given time.

## How it works.

You have a secret you wish to share, but you don't want to paste the credentials into an email/IM.

The sharer uses the web client which:

- Asks for the secret, a passphrase and a TTL.
- Uses the passphrase to derive an encryption key.
- Encrypts the secret with the encryption key.
- Creates a hash of the encryption key.
- The client calls out to the server and sends the encrypted secret and the hash of the passphrase.
- The server stores both the encrypted secret and the hash of the passphrase and the expiry and returns an opaque key.

The sharer gives the key and the passphrase to the recipient, who then uses the web client which:

- Asks for the key (although this is probably encoded in the URL)
- Asks for the passphrase, derives the key and hash
- Calls out to the server for with the key and the hash.
- The server checks the key and the hash (and the expiry) and if OK, returns the encrypted secret and destroys the record
- The client decrypts the secret and displays to the recipient.

## API and Routes

- `/send` HTML Client for creating a secret to share
- `/recv(?key=<key>)` HTML Client for receiving a secret
- `POST /api/send` with `enc=<encrypted secret>&hash=<hash of passphrase>&ttl=<seconds to keep>` returns JSON `{"key": "<key or null>", "errors": ["<string>"]}`
- `POST /api/recv` with `key=<key>&hash=<hash>` returns JSON `{"enc":"<encrypted secret or null>","errors": ["<string>"]}`

That's it.

## Why?

Because I fancied doing as much of this in the client with JS as possible as an experiment in WebCrypto. As such support is limited to browsers with proper WebCrypto support.
