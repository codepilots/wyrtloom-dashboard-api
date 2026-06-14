# Writing a client of the Wyrtloom dashboard API

The Wyrtloom dashboard API (`wyrtloom-dashboard-api`) is **frontend-agnostic**:
the React SPA is just one client. Any client — a mobile app, a CLI, a native
program, another service — can talk to it as long as it implements the same two
mechanisms:

1. **Client-signature auth** — every request (except `/api/enroll`) carries a
   per-request signature in four `x-wyrtloom-*` headers, proving it comes from an
   enrolled client holding a private key, and that it is fresh.
2. **Session auth** — role-gated endpoints additionally require a bearer session
   token obtained from `/api/login`.

The browser SPA's signing code (`wyrtloom-dashboard-web/src/crypto/canonical.ts`,
`clientKey.ts`) and the server's verifier (`wyrtloom-dashboard-api/src/auth.rs`,
core `client_auth.rs`, and `wyrtloom-clientauth-tofu`) are the authoritative
reference; this document tells you how to reproduce them in a new client.

The API runs as a **single instance** (its nonce-replay cache is process-local),
so point all clients at one endpoint.

---

## 1. Enrollment (first run, once per client)

A brand-new client has no identity. It generates a keypair, then trades an
operator-issued **single-use bootstrap key** for a `client_id`. The enroll
request is the **only** request that is *not* client-signed (it is how a client
first authorizes itself).

```
POST /api/enroll
Content-Type: application/json

{
  "api_key": "<single-use bootstrap key, provided out-of-band by an operator>",
  "client_name": "my-cli-on-laptop",
  "public_key_b64": "<STANDARD base64 of your raw public key>"
}
```

- **`public_key_b64`** is **standard** base64 (not base64url) of the **raw**
  public key bytes:
  - ed25519: the 32-byte public key.
  - ECDSA P-256: the **65-byte SEC1 uncompressed** point — `0x04 || X || Y`.
- The server base64-decodes it and passes the raw bytes to the client-auth
  scheme, which detects the algorithm **by length** (32 ⇒ ed25519, 65 with
  leading `0x04` ⇒ P-256).

On success you get:

```json
{ "client_id": "<hex fingerprint>" }
```

Under the reference TOFU scheme the `client_id` equals the SHA-256 fingerprint of
your public key (trust-on-first-use pinning). **Persist `client_id` together with
your keypair** — you need both for every subsequent request. The enroll request
is rate-limited per source IP; a wrong/spent bootstrap key returns `401` with a
generic `"enrollment rejected"` (the server deliberately does not say which step
failed).

Operator side: a bootstrap key is issued out-of-band and is **single-use**
(atomically consumed on first successful enrollment). Re-enrolling the *same*
public key is idempotent and consumes no additional key.

### Key storage

Keep the **private key non-exportable** wherever the platform allows it. The
browser SPA generates a **non-extractable** WebCrypto P-256 keypair: even XSS can
ask it to sign, but the private bytes can never be read back. A native client
should use the OS keystore / secure enclave for the same property; a CLI should
at minimum store the key in a `0600` file and never log it.

---

## 2. Per-request signing

Every request other than `/api/enroll` must carry these four headers:

| Header                  | Value |
|-------------------------|-------|
| `x-wyrtloom-client`     | your `client_id` |
| `x-wyrtloom-timestamp`  | current Unix time in **decimal seconds** (e.g. `"1700000000"`) |
| `x-wyrtloom-nonce`      | a fresh random value per request (the SPA uses 16 random bytes as lowercase hex) |
| `x-wyrtloom-signature`  | **lowercase hex** of the raw signature over the canonical bytes |

The signature is computed over the **canonical request bytes** (§2.1) using your
private key (§2.2).

### 2.1 The canonical bytes

The server canonicalizes via `wyrtloom_core::client_auth::canonical_request`; the
browser reproduces it byte-for-byte in `canonical.ts`. The construction is:

- A **domain tag** prefix: the ASCII string `wyrtloom-client-auth-v1`.
- Then six fields, in this fixed order:
  1. `method` — UTF-8 (e.g. `"POST"`, `"GET"`)
  2. `path` — UTF-8, the **full path + query string** (`path_and_query`) — see §4
  3. `body_sha256` — the raw **32 bytes** of `SHA-256(request body bytes)` (for an
     empty body, the SHA-256 of the empty string)
  4. `client_id` — UTF-8
  5. `timestamp` — the i64 Unix-seconds value as **8 bytes big-endian**
     (two's-complement)
  6. `nonce` — UTF-8

Every field — **including the domain tag** — is written as an **8-byte
big-endian unsigned length prefix** followed by its raw bytes. There are no
separators beyond the length prefixes. In pseudocode:

```
fields = [ utf8("wyrtloom-client-auth-v1"),
           utf8(method),
           utf8(path),                    // path_and_query, see §4
           body_sha256,                   // exactly 32 bytes
           utf8(client_id),
           i64_be(timestamp),             // 8 bytes, big-endian two's-complement
           utf8(nonce) ]

out = []
for f in fields:
    out ||= u64_be(len(f))   // 8-byte big-endian length
    out ||= f
signed_bytes = out
```

**Golden vector** (from `canonical.test.ts` — keep it byte-identical or the
server will reject your signatures). Inputs: method `POST`, path `/api/login`,
`body_sha256` = 32 bytes all `0xab`, `client_id` `abc`, `timestamp`
`1700000000`, `nonce` `n1`. The resulting bytes in hex:

```
0000000000000017                                  len(domain) = 23
777972746c6f6f6d2d636c69656e742d617574682d7631    "wyrtloom-client-auth-v1"
0000000000000004                                  len(method) = 4
504f5354                                          "POST"
000000000000000a                                  len(path) = 10
2f6170692f6c6f67696e                              "/api/login"
0000000000000020                                  len(body_sha256) = 32
abababababababababababababababababababababababababababababababab
0000000000000003                                  len(client_id) = 3
616263                                            "abc"
0000000000000008                                  len(timestamp bytes) = 8
000000006553f100                                  1700000000 as i64 BE
0000000000000002                                  len(nonce) = 2
6e31                                              "n1"
```

### 2.2 Algorithms and the mandatory P-256 low-s rule

You may sign with **either**:

- **ed25519** (32-byte public key): sign the canonical bytes; the signature is the
  standard 64-byte raw ed25519 signature.
- **ECDSA P-256 / secp256r1** (65-byte SEC1 public key): sign `SHA-256(canonical
  bytes)` per ECDSA; the signature is the 64-byte raw `r ‖ s` (32 bytes each).

For **P-256 you MUST normalize to low-s.** The server only accepts canonical
**low-s** signatures (anti-malleability) and rejects high-s. WebCrypto's
`crypto.subtle.sign` (and many other libraries) emit high-s roughly half the
time, so a client that does not normalize will be rejected ~50% of requests.

Normalization: if `s > n/2`, replace `s` with `n − s` (leave `r` unchanged),
where `n` is the P-256 group order. Both forms verify the same message; only the
low-s form is accepted.

```
n      = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
n_half = n >> 1

function normalize_low_s(sig_64):          // sig_64 = r(32) || s(32), big-endian
    s = int_be(sig_64[32..64])
    if s <= n_half:
        return sig_64                       // already low-s
    v = n - s
    return sig_64[0..32] || int_be_32(v)    // r unchanged, s := n - s
```

(Rust verifiers use `p256::ecdsa::Signature::normalize_s()` and reject when it
reports the signature was high-s; a browser client runs the pseudocode above on
the raw 64-byte signature before hex-encoding it. See `clientKey.ts`
`normalizeLowS` and `wyrtloom-clientauth-tofu`'s `verify_signature`.)

Finally, hex-encode the (low-s, for P-256) raw signature in **lowercase** and put
it in `x-wyrtloom-signature`.

### 2.3 Freshness and replay

The server checks the timestamp against a skew window (±300 s by default) and
rejects a `(client_id, nonce)` pair it has already seen within the trailing skew
window. So: use a real current timestamp, and a **fresh** nonce per request.
Clock drift beyond the skew window fails closed (`401`).

---

## 3. Session flow (login → bearer token)

Client-signature auth proves *which client* is calling. Role-gated endpoints
additionally require a *user session*. Obtain one from `/api/login` — which is
itself a **client-signed** request (it is `ClientOnly`: signature required, no
session yet), rate-limited per IP:

```
POST /api/login            (client-signed: x-wyrtloom-* headers required)
Content-Type: application/json

{ "username": "alice", "password": "…" }
```

Success:

```json
{ "token": "<bearer token>", "exp_unix": 1700003600 }
```

Send the token on every subsequent role-gated request **in addition to** the
client signature:

```
Authorization: Bearer <token>
x-wyrtloom-client: …
x-wyrtloom-timestamp: …
x-wyrtloom-nonce: …
x-wyrtloom-signature: …
```

**401 handling / expiry.** A `401` on a role-gated request means the session is
expired/invalid — drop the token and re-login. The token has an expiry
(`exp_unix`); the server rejects an expired token before doing any other work, and
also rejects revoked tokens. `/api/logout` (a `Viewer`-role, client-signed +
bearer request) revokes the current token's nonce on the durable denylist; after
logout the token is unusable. Note: a `401` from `/login` or `/logout` itself
means *bad credentials / already-gone session*, not an expired in-app session —
do not treat it as "session expired" and loop.

Keep the bearer token **in memory** where possible (the SPA never puts it in
`localStorage`/`sessionStorage`). A native/CLI client should keep it in process
memory and re-login on expiry rather than persisting it.

---

## 4. The path-must-be-`path_and_query` caveat

The server canonicalizes over the request URI's **`path_and_query`** — so the
query string is integrity-protected, not just the path. The string you **sign**
and the string you **send** must be byte-identical, including query encoding.

- Sign over `pathname + search` of the exact URL you fetch (e.g.
  `/api/board?states=Todo%2CRunning`), **not** the bare path.
- Build the query through a proper encoder (`URLSearchParams` in JS; your
  platform's equivalent), and sign **that same** encoded string. Do **not**
  hand-concatenate a query that might encode differently from what is actually
  sent on the wire — a divergent encoding signs one string and sends another,
  producing a self-inflicted `401`. (The SPA locks this with a round-trip test:
  `signedPath === sentPath === the string the canonical bytes cover`.)
- An empty-body `GET` still uses `body_sha256 = SHA-256("")`.

---

## 5. RBAC: roles and endpoints

The session carries roles, but the server **re-fetches the user** on every
request and trusts the user directory's *current* roles + `active` flag — never
the token's snapshot. Roles are explicit and **not** hierarchical: holding
`Admin` does **not** imply `Viewer`. Operators grant `Viewer` alongside
`Operator`/`Admin` as needed.

| Method & path                         | Required auth                | Role     |
|---------------------------------------|------------------------------|----------|
| `POST /api/enroll`                    | PublicBootstrap (unsigned)   | —        |
| `POST /api/login`                     | ClientOnly (signed, no session) | —     |
| `POST /api/logout`                    | signed + session             | Viewer   |
| `GET  /api/board`                     | signed + session             | Viewer   |
| `GET  /api/tasks/:id`                 | signed + session             | Viewer   |
| `GET  /api/plugins`                   | signed + session             | Viewer   |
| `POST /api/tasks`                     | signed + session             | Operator |
| `POST /api/tasks/:id/transition`      | signed + session             | Operator |
| `POST /api/tasks/:id/claim`           | signed + session             | Operator |
| `POST /api/tasks/:id/block`           | signed + session             | Operator |
| `GET  /api/config`                    | signed + session             | Admin    |
| `PUT  /api/config`                    | signed + session (TOML body) | Admin    |
| `GET  /api/logs`                      | signed + session             | Admin    |
| `GET  /api/audit`                     | signed + session             | Admin    |

The router is **default-deny**: there is no "open" tier. A request missing the
required role returns `403` (`"forbidden"`); a request missing/failing client
signature or session returns `401`. `PUT /api/config` takes a raw **TOML** body
(`Content-Type: text/plain`), so hash and sign those exact bytes.

---

## 6. Worked example

A reference signing client lives in the SPA's `src/crypto/` (`canonical.ts`,
`clientKey.ts`, `sha256.ts`) and its fetch wrapper `src/api/client.ts`. Any
client reduces to this per-request recipe (Node/WebCrypto-style pseudocode for a
P-256 client; ed25519 is the same minus the low-s step):

```js
async function signedFetch(method, path, query, bodyBytes, clientId, privateKey) {
  // 1. Resolve the exact path+query you will send, and sign that same string.
  const url = buildUrl(path, query);          // via URLSearchParams — never hand-built
  const signedAndSentPath = new URL(url, origin).pathname
                          + new URL(url, origin).search;

  // 2. Canonical bytes (see §2.1) — byte-identical to the server.
  const bodySha256 = sha256(bodyBytes);        // 32 raw bytes; sha256("") for empty body
  const timestamp  = Math.floor(Date.now() / 1000);
  const nonce      = randomHex(16);
  const canonical  = buildCanonicalBytes({
    method, path: signedAndSentPath, bodySha256, clientId, timestamp, nonce,
  });

  // 3. Sign, then (P-256 only) normalize to low-s, then lowercase-hex.
  let sig = await ecdsaP256Sign(privateKey, canonical);   // 64-byte r||s
  sig = normalizeLowS(sig);                                // §2.2 — mandatory for P-256
  const signatureHex = toHex(sig);

  // 4. Send the SAME url, with the four headers (+ bearer for role-gated routes).
  return fetch(url, {
    method,
    headers: {
      'x-wyrtloom-client':    clientId,
      'x-wyrtloom-timestamp': String(timestamp),
      'x-wyrtloom-nonce':     nonce,
      'x-wyrtloom-signature': signatureHex,
      // 'Authorization': `Bearer ${sessionToken}`  // role-gated endpoints
      // 'Content-Type': 'application/json'          // when there is a body
    },
    body: bodyBytes.length ? bodyText : undefined,
  });
}
```

Validate your client against the golden vector in §2.1 before going near the
network: if `buildCanonicalBytes` of the golden inputs does not produce the
quoted hex byte-for-byte, your signatures will be rejected.
