![Poof Magazine](assets/poof.png)

# poof! magically disappearing secret sharing

Lots of prior work in this field (citation required), but I figured I could have a go and see about leveraging the new `WebCrypto` APIs.

`poof` allows you to securely share secrets in a self-destructing, time-limited, passphrase protected way.

- The server never sees the secret, or the passphrase.
- The server only ever releases the encrypted secret once, within the given time.

All data held in memory so server reload drops all secrets.

## Demo

A demo server is running at https://poof.0x6377.dev/.

But don't trust me --- run your own!

## Installation

- Build from source with `go build` from the repo
- Build from source and install with `go get github.com/thechriswalker/poof`

Produces a single binary `poof` that will run a web server on port 5000 or specify a different port with `-port=X`

## How it works.

You have a secret you wish to share, but you don't want to paste the credentials into an email/IM.

The sharer uses the web client which:

- Asks for the secret, ~a passphrase~ and a TTL. (_passphrase is just randomly generated_)
- Uses the passphrase to derive an encryption key.
- Encrypts the secret with the encryption key.
- Creates a hash of the encryption key.
- The client calls out to the server and sends the encrypted secret and the hash of the passphrase.
- The server stores both the encrypted secret and the hash of the passphrase and the expiry and returns an opaque key.

The sharer gives the ~key and the passphrase~ _URL_ (which contains the passphrase and key in the hash fragment) to the recipient, who then uses the web client which:

- ~Asks for the key (although this is probably encoded in the URL)~ _Gets the key from hash fragment_
- ~Asks for the passphrase~ _Gets the passphrase from hash fragment_, derives the key and hash
- Calls out to the server for with the key and the hash.
- The server checks the key and the hash (and the expiry) and if OK, returns the encrypted secret and destroys the record
- The client decrypts the secret and displays to the recipient.

## API and Routes

- `/send` HTML Client for creating a secret to share
- `/recv#key=<key>&pass=<pass>` HTML Client for receiving a secret
- `POST /api/send` with `enc=<encrypted secret>&hash=<hash of passphrase>&ttl=<seconds to keep>` returns JSON `{"key": "<key or null>", "errors": ["<string>"]}`
- `POST /api/recv` with `key=<key>&hash=<hash>` returns JSON `{"enc":"<encrypted secret or null>","errors": ["<string>"]}`

That's it.

## Why?

Because I fancied doing as much of this in the client with JS as possible as an experiment in WebCrypto. As such support is limited to browsers with proper WebCrypto support.

### Why "poof"?

Seriously, go watch Arrested Development. It's awesome -- you won't regret it.
