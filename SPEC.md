# Envelope format, version 1

This is the byte format of `@ecies/threshold` envelopes and shares, and the steps that create and open them. It is a draft until 0.1.0 is released. The design discussion is in [#1](https://github.com/ecies/js-threshold/issues/1).

## Overview

An envelope encrypts a message so that any K of its N recipients, together, can open it.

```text
encrypt(recipients[N], K, plaintext, aad)
  dk         ← 32 random bytes                       the data key
  share_i    ← Shamir split of dk, one per recipient  33 bytes each
  prelude    ← version | suite | K | N | keyCheck(dk) | N × (fingerprint(pk_i) | commitment(share_i))
  wrapped_i  ← ECIES(pk_i, share_i), bound to i and the prelude
  header     ← prelude | wrapped_0 … wrapped_{N−1}
  content    ← AEAD(contentKey(dk), nonce, header ‖ aad, plaintext)
  return header ‖ content

decryptShare(sk_i, envelope)   → share_i, in the share format below
combine(envelope, K or more shares, aad) → plaintext
```

This is threshold access control, not threshold decryption: `combine` reassembles the data key wherever it runs.

## Conventions

- Lengths are in bytes. Every integer field is one unsigned byte, and `byte(i)` is `i` as one.
- `‖` is concatenation, and `|` separates fields in a layout.
- SHA-256 is FIPS 180-4. HKDF is RFC 5869 with SHA-256.
- Domain strings are ASCII, with no terminator.
- Recipient indexes and share positions count from 0.

## Suites

The suite byte fixes the curve, the ECIES options and the cipher. One cipher both wraps the shares and encrypts the content. The columns are the fields of eciesjs 0.5's `Config`:

- **Ephemeral key:** `isEphemeralKeyCompressed`;
- **HKDF input:** `isHkdfKeyCompressed`;
- **Cipher and Nonce:** `symmetricAlgorithm` and `symmetricNonceLength`.

`W` is the size of a wrapped share: the ephemeral public key, then the nonce, the 16-byte tag and the 33-byte encrypted share.

| ID | Curve | Ephemeral key | HKDF input | Cipher | Nonce | W |
|---|---|---|---|---|---|---|
| `0x01` | secp256k1 | uncompressed | uncompressed | AES-256-GCM | 16 | 130 |
| `0x02` | secp256k1 | uncompressed | uncompressed | AES-256-GCM | 12 | 126 |
| `0x03` | secp256k1 | uncompressed | uncompressed | XChaCha20-Poly1305 | 24 | 138 |
| `0x04` | secp256k1 | compressed | uncompressed | AES-256-GCM | 16 | 98 |
| `0x05` | secp256k1 | compressed | uncompressed | AES-256-GCM | 12 | 94 |
| `0x06` | secp256k1 | compressed | uncompressed | XChaCha20-Poly1305 | 24 | 106 |
| `0x07` | secp256k1 | uncompressed | compressed | AES-256-GCM | 16 | 130 |
| `0x08` | secp256k1 | uncompressed | compressed | AES-256-GCM | 12 | 126 |
| `0x09` | secp256k1 | uncompressed | compressed | XChaCha20-Poly1305 | 24 | 138 |
| `0x0a` | secp256k1 | compressed | compressed | AES-256-GCM | 16 | 98 |
| `0x0b` | secp256k1 | compressed | compressed | AES-256-GCM | 12 | 94 |
| `0x0c` | secp256k1 | compressed | compressed | XChaCha20-Poly1305 | 24 | 106 |
| `0x11` | x25519 | | | AES-256-GCM | 16 | 97 |
| `0x12` | x25519 | | | AES-256-GCM | 12 | 93 |
| `0x13` | x25519 | | | XChaCha20-Poly1305 | 24 | 105 |
| `0x21` | ed25519 | | | AES-256-GCM | 16 | 97 |
| `0x22` | ed25519 | | | AES-256-GCM | 12 | 93 |
| `0x23` | ed25519 | | | XChaCha20-Poly1305 | 24 | 105 |

- **Defaults:** `0x01` is eciesjs's default `Config`.
- **Options eciesjs ignores:** for x25519 and ed25519 eciesjs ignores both compression options, and for XChaCha20-Poly1305 it ignores the nonce length. So any such `Config` maps to the row above.
- **Reserved values:**
  - `0x00` is never valid.
  - `0x80`–`0xff` are reserved for post-quantum and hybrid suites.
  - Every other value not listed is reserved too. Adding a suite doesn't change the envelope version.
- **The ciphers:** AES-256-GCM is NIST SP 800-38D, with a 16-byte tag; with a 16-byte nonce, GCM derives its initial counter block with GHASH. XChaCha20-Poly1305 is draft-irtf-cfrg-xchacha, with a 24-byte nonce and a 16-byte tag.

## Keys and fingerprints

A public key is valid on the suite's curve when it meets the rules below. `encrypt` checks each recipient key, and fails with `InvalidArgument` on an invalid one. `decryptShare` checks the ephemeral key in the wrapped share (see [Unwrapping](#wrapped-shares)).

- **secp256k1:** a SEC1 point, compressed (33 bytes) or uncompressed (65 bytes), on the curve.
- **x25519:** 32 bytes holding a canonical u-coordinate, below 2^255 − 19 (so bit 255 is clear), and not of small order: its X25519 shared secret must not be all zeros (RFC 7748, section 6.1).
  - X25519 clamps every scalar to a multiple of 8, so a small-order point gives all zeros whatever the secret key. Any key can test it, so `encrypt` can check a recipient key before it draws `e`.
- **ed25519:** 32 bytes holding a canonical RFC 8032 encoding (y below 2^255 − 19). The point must lie on the curve and in the prime-order subgroup, and must not be of small order.
  - The identity point passes the subgroup check, so the small-order check is what rejects it.
  - Without these checks, the identity point as a recipient key gives a shared point anyone can compute, and so a share anyone can unwrap.
- **Byte order:** x25519's u and ed25519's y are little-endian (RFC 7748, RFC 8032). secp256k1 coordinates and secret keys are big-endian (SEC1).
  - An X25519 implementation may mask bit 255 of u, or reduce u modulo 2^255 − 19, instead of rejecting a non-canonical value. `@noble/curves` 1.9's does both. So an implementation checks that u is canonical itself.

A secret key must be 32 bytes. On secp256k1 it must also lie strictly between 0 and the group order. Otherwise `decryptShare` fails with `InvalidArgument`.

A recipient's canonical public key `pk*` is:

- for secp256k1, the 33-byte compressed SEC1 point, whichever form the caller passed;
- for x25519, the 32-byte u-coordinate;
- for ed25519, the 32-byte Ed25519 public key.

```text
fingerprint = SHA-256("ecies-threshold/v1/fingerprint" ‖ pk*)
```

A holder finds their entry by computing their own fingerprint, with no trial decryption. The fingerprint is computed from the public key that `decryptShare` derives from the secret key. That's why x25519 keys must be canonical: a key with bit 255 set unwraps the same way, but its fingerprint wouldn't match.

Recipients must be distinct by `pk*`, since one person holding two shares lowers the real threshold. This catches the same key passed twice, in any encoding. It doesn't catch distinct keys that one secret key can unwrap. On x25519, for example, `pk` and `pk` plus a small-order point are such a pair. `decryptShare` still finds only the entry whose fingerprint matches the holder's own key.

## Envelope

```text
offset          size     field
0               1        version = 0x01
1               1        suite
2               1        threshold K
3               1        recipients N
4               32       key check
36              N × 64   recipient table, entry i at 36 + 64·i:
                           +0    32   fingerprint_i
                           +32   32   commitment_i
P = 36 + 64·N   N × W    wrapped shares, wrapped_i at P + W·i
H = P + N·W     Ln       nonce            (Ln = the suite's nonce length)
H + Ln          16       tag
H + Ln + 16     rest     ciphertext
```

- **Prelude:** the first `P = 36 + 64·N` bytes are the prelude: everything in the header except the wrapped shares. The wrapped shares and the envelope id are both bound to it.
- **Header:** the header is the first `H = 36 + N·(64 + W)` bytes, and the content is everything after it.
- **Size:** the envelope is `H + Ln + 16 + |plaintext|` bytes.
  - For example, 2-of-3 with suite `0x01` takes 194 bytes per recipient. It has a 618-byte header and 650 bytes of overhead.
- **Limits:** 2 ≤ K ≤ N ≤ 255. K = 1 is plain multi-recipient encryption, which is out of scope.

## Secret sharing

- **Data key:** the data key `dk` is 32 bytes from a CSPRNG.
- **Field:** GF(2^8) with the reduction polynomial x⁸ + x⁴ + x³ + x + 1 (`0x11b`), the AES field. Addition is XOR.
- **Polynomials:** for each byte position `t` from 0 to 31, a polynomial `f_t` of degree K − 1. Its constant term is `dk[t]`, and its other coefficients are uniformly random.
- **x-coordinates:** `x_0 … x_{N−1}` are distinct and non-zero. They aren't secret. The reference implementation shuffles 1–255 at random, but any distinct non-zero values are valid.
- **Shares:** `share_i = f_0(x_i) ‖ … ‖ f_31(x_i) ‖ x_i`, 33 bytes. `share_i` goes to recipient `i`, in the order `encrypt` was given.
- **Commitment:**

  ```text
  commitment_i = SHA-256("ecies-threshold/v1/share" ‖ share_i)
  ```

- **Recovery:** byte by byte, Lagrange interpolation through the first K supplied shares, `j, m` in `0 … K−1`. In a field of characteristic 2, subtraction is addition, so:

  ```text
  f_t(x) = Σ_j  y_j[t] · Π_{m ≠ j}  (x + x_m) / (x_j + x_m)
  dk[t]  = f_t(0)
  ```

  Every share after the first K must lie on the same polynomials: `f_t(x_s) = y_s[t]` for every `t`. Otherwise the shares aren't all from one polynomial of degree K − 1. Interpolating through all M supplied shares instead would accept a polynomial of degree up to M − 1, so an envelope could open with M shares while every K-subset fails.

## Wrapped shares

Each share is wrapped with eciesjs 0.5's ECIES, with one addition: the AEAD takes associated data that binds the wrapped share to its envelope.

```text
wrapAD_i  = "ecies-threshold/v1/wrap" ‖ byte(i) ‖ prelude

e         ← a fresh secret key on the suite's curve
E         = e's public key, encoded per the suite's "Ephemeral key" column
S         = e's public key, encoded per the suite's "HKDF input" column     (the sender point)
Z         = the shared point, encoded per the suite's "HKDF input" column
k         = HKDF(IKM = S ‖ Z, salt = empty, info = empty, L = 32)
nonce     ← Ln random bytes
ct, tag   ← AEAD-Encrypt(k, nonce, AD = wrapAD_i, share_i)

wrapped_i = E ‖ nonce ‖ tag ‖ ct                                            (W bytes)
```

The point encodings depend on the curve:

- **secp256k1:**
  - `E` is 65 bytes uncompressed or 33 compressed, per "Ephemeral key".
  - `S` and `Z = e·pk` are SEC1 points, 65 or 33 bytes, per "HKDF input".
- **x25519:** `E = S = X25519(e, 9)` and `Z = X25519(e, pk)`, 32 bytes each.
- **ed25519:**
  - `E = S` is e's RFC 8032 public key.
  - `Z = [s]·pk` is a 32-byte Edwards point encoding. `s` is e's RFC 8032 secret scalar: SHA-512 of `e`, clamped, then reduced modulo the group order.
  - This is not a conversion to X25519.

**Unwrapping:** the recipient reads `E` and checks it, re-encodes it as `S`, computes `Z` with its own secret key (`sk·E`, `X25519(sk, E)` or `[s]·E`), derives `k` and decrypts with the same `wrapAD_i`.

- **The check:** `E` must be a valid public key on the suite's curve (see [Keys and fingerprints](#keys-and-fingerprints)). On secp256k1 it must also be in the suite's "Ephemeral key" form: `0x04` and 64 bytes, or `0x02` or `0x03` and 32 bytes. An honest encryptor's `E` always passes.
- **Why, on ed25519:** eciesjs 0.5 checks only that `E` decodes to a point on the curve.
  - **The identity point** as `E` gives the identity as `Z` whatever the secret key, so anyone can unwrap that share. Its holder's `decryptShare` still succeeds and shows nothing wrong.
  - **A point outside the prime-order subgroup,** `[r]·B + T` with `T` of order 8, makes `Z` depend on how `s` was reduced. Reduced modulo the group order, as above, `s mod 8` depends on ⌊clamped / group order⌋, which is 3 to 7. So whether unwrapping succeeds reveals about 2 bits of the holder's secret scalar to anyone who can send them envelopes and see which open. An implementation that multiplies by the clamped scalar unreduced gets a different `Z` instead.
  - In the prime-order subgroup, both scalars give the same `Z`, and it reveals nothing.

**Compatibility:** with empty associated data, this is exactly eciesjs 0.5's `encrypt`. Its [DETAILS.md](https://github.com/ecies/js/blob/master/DETAILS.md) predates the sender point and doesn't cover x25519 or ed25519, so the steps above are the reference.

**Why the binding:** without `wrapAD_i`, an entry could be copied whole (fingerprint, commitment and wrapped share) into another envelope.

- **The attack:** a holder asked to approve that decoy would unwrap a share that matches the copied commitment, and hand over their share of the original.
- **With the binding:** the decoy's prelude differs, so unwrapping fails (`ShareDecryptionFailed`). The index `i` keeps an entry from moving to another position in the same envelope.

## Key check and content

```text
contentKey = HKDF(IKM = dk, salt = empty, info = "ecies-threshold/v1/content",   L = 32)
keyCheck   = HKDF(IKM = dk, salt = empty, info = "ecies-threshold/v1/key-check", L = 32)

nonce                 ← Ln random bytes
ciphertext, tag       ← AEAD-Encrypt(contentKey, nonce, AD = header ‖ aad, plaintext)
content               = nonce ‖ tag ‖ ciphertext
```

- **Caller's `aad`:** `aad` is the caller's associated data, empty when there is none. It isn't stored, so `combine` must be given the same bytes. The header records its own length, so `header ‖ aad` splits only one way.
- **Why the key check:** AES-GCM and XChaCha20-Poly1305 don't commit to their key, and share commitments don't check that the shares lie on one polynomial.
  - Without the check, an encryptor could pick shares whose K-subsets interpolate to different keys, plus a ciphertext that opens under more than one of them, so different groups of holders would read different plaintexts.
  - The key check pins one data key, so every K-subset either reconstructs that key or fails.

## Share format

`decryptShare` returns a share in this format. It travels from its holder to whoever runs `combine`.

```text
offset  size  field
0       1     version = 0x01
1       32    envelope id = SHA-256("ecies-threshold/v1/envelope-id" ‖ prelude)
33      1     recipient index i, below N
34      33    share_i
```

- **Size:** 67 bytes.
- **Envelope id:** a share from another envelope is reported as such, instead of failing its commitment and blaming its holder.
- **Why the full hash:** the envelope's creator chooses both preludes, so a shorter id falls to a birthday search. With a 16-byte id, about 2^64 work would give two envelopes one id. A holder's share of the first would then fail the second's commitment and be blamed on them. The full hash takes about 2^128.
- **What the id names:** the id covers the prelude, the same bytes the wrapped share is bound to. Any envelope with that prelude has the same data key and shares, so a holder approving a release should approve this id. The exception is an encryptor reusing a data key across envelopes (see [Security considerations](#security-considerations)).
- **Not an authenticator:** the id is public, so anyone can rewrite it. It labels a share; it doesn't prove where the share came from.
- **Secrecy:** a share is a secret, since K of them open the envelope. Send it over a confidential channel, for example ECIES-encrypted to the combiner's key.

## Procedures

Errors are named after the conditions below. An implementation can report them in its own way, for example as error classes.

### encrypt(recipients, K, plaintext, aad, config)

`aad` defaults to empty, and `config` to eciesjs's default `Config`, which is suite `0x01`.

1. **Validate the inputs.** Map `config` to a suite and check 2 ≤ K ≤ N ≤ 255. Check that every public key is valid on the suite's curve (see [Keys and fingerprints](#keys-and-fingerprints)), and compute its `pk*`. If any of these fails, or two `pk*` are equal: `InvalidArgument`.
2. **Split the data key.** Draw `dk`, then split it into N shares with threshold K.
3. **Build the prelude.** Compute `keyCheck`, each fingerprint and commitment, then the prelude.
4. **Wrap the shares.** Wrap each share with its `wrapAD_i`, then append the wrapped shares to make the header.
5. **Encrypt the content.** Draw the nonce and encrypt the plaintext with `contentKey`.
6. **Return** `header ‖ nonce ‖ tag ‖ ciphertext`.

On every path, success or failure, zero `dk`, `contentKey` and the shares, as far as the platform allows.

### Parsing an envelope

Both `decryptShare` and `combine` start here. Each check runs in order, before any decryption, and the first to fail decides the error.

1. **Length:** at least 4 bytes, else `MalformedEnvelope`.
2. **Version:** `0x01`, else `UnsupportedVersion`.
3. **Suite:** listed in the suite table, else `UnsupportedSuite`.
4. **Threshold:** 2 ≤ K ≤ N, else `MalformedEnvelope`.
5. **Length again:** at least `H + Ln + 16` bytes, else `MalformedEnvelope`.
6. **Fingerprints:** pairwise distinct, else `MalformedEnvelope`.
7. **Commitments:** pairwise distinct, else `MalformedEnvelope`.

### decryptShare(sk, envelope)

1. **Parse** the envelope.
2. **Check the secret key.** If `sk` isn't a valid secret key on the suite's curve: `InvalidArgument`.
3. **Find the entry.** Derive `pk*` from `sk`, then find the entry with its fingerprint. If there is none: `NotARecipient`.
4. **Unwrap.** Check `E`, then unwrap `wrapped_i` with `sk` and `wrapAD_i` (see [Unwrapping](#wrapped-shares)). If `E` is invalid or decryption fails: `ShareDecryptionFailed`. The share isn't for `sk`, or the entry was altered, crafted or copied from another envelope.
5. **Check the commitment.** If the share doesn't match `commitment_i`: `CommitmentMismatch`. The envelope was built wrong, and this share must not be handed in.
6. **Check the x-coordinate.** If it is 0: `MalformedShare`.
7. **Return** the share in the share format.

On every path, zero the unwrapped share's copies that aren't returned.

### combine(envelope, shares, aad)

`aad` defaults to empty.

A share's position `p` is its place in the `shares` argument. Each step checks every share before the next step starts. Each share error lists every failing position, in order.

1. **Parse** the envelope.
2. **Check the shape.** Each share must be 67 bytes with version `0x01`. Otherwise: `MalformedShare`.
3. **Check the envelope id.** Each share's id must match this envelope's. Otherwise: `WrongEnvelope`.
4. **Check the index and x-coordinate.** Each share's index must be below N, and its x-coordinate must not be 0. Otherwise: `MalformedShare`.
5. **Check the commitments.** Each share must match `commitment_i` for the index `i` it names. Otherwise: `CommitmentMismatch`.
6. **Check for duplicates.** No two shares may name the same index. Otherwise: `DuplicateShare`, listing the positions that repeat an earlier one.
7. **Count.** There must be at least K shares. Otherwise: `NotEnoughShares`.
8. **Check the x-coordinates.** No two shares may share an x-coordinate. Otherwise: `InconsistentShares`.
9. **Interpolate.** Find `dk` from the first K shares, in position order.
10. **Check the key.** Compare `keyCheck(dk)` with the stored key check, in constant time. If they differ: `InconsistentShares`.
11. **Check the remaining shares.** Every share after the first K must lie on the same polynomials. Otherwise: `InconsistentShares`.
12. **Decrypt the content** with `contentKey` and `AD = header ‖ aad`. If that fails: `DecryptionFailed`, because the `aad` is wrong or the envelope was altered.
13. **Return** the plaintext.

On every path, success or failure, zero `dk`, `contentKey` and the share copies, as far as the platform allows. A wrong `aad` fails at step 12 with the real keys in memory.

**Who causes each failure:**
- Steps 8, 10 and 11 can't come from holders: every share already matched its commitment. Only the envelope's creator can cause them.
- Step 5 comes before step 6 so that a forged share claiming an honest holder's index is reported as `CommitmentMismatch` at its own position, not as a duplicate of the honest share.

**Strict by design:** `combine` fails as a whole when any share fails. It doesn't open the envelope with the rest.

**Finding who handed in a bad share:** when the error is `CommitmentMismatch` or `MalformedShare`, the caller can drop the named shares and call `combine` again with others.
- If the content then opens, the header is as its creator made it.
- An honest holder's share passed this same commitment at step 5 of `decryptShare`, since the envelope id ties it to this prelude. So the dropped share isn't what its holder's `decryptShare` returned: the holder is dishonest, or the share was altered on its way.
- `WrongEnvelope` says nothing of the sort. An honest holder may simply have unwrapped a different envelope.

## Security considerations

- **The combiner** learns the data key and the plaintext.
- **Fewer than K shares:** Shamir alone reveals nothing about the data key. The header adds the fingerprints, the commitments and the key check. With K − 1 shares, finding the data key still takes about 2^256 guesses, each checked against the key check.
- **A dishonest encryptor:**
  - **Can't:**
    - make different K-subsets open different plaintexts (the key check);
    - make an envelope that opens with more than K shares while its K-subsets fail (the degree check in `combine`);
    - hand a holder a share that doesn't match its commitment without that holder's `decryptShare` failing.
  - **Can:** make an envelope that some or all K-subsets fail to open (`InconsistentShares`). Nothing authenticates the encryptor (see below).
- **What a holder releases:** a share opens the envelopes its envelope id names.
  - Copying an entry into a decoy envelope fails at unwrapping, because the wrapped share is bound to its prelude.
  - An encryptor who reuses a data key and shares across envelopes can still make one share fit several of them. Nothing in the format can stop that, since the encryptor already knows the data key.
- **Attribution:** a bad share is reported by its position in `combine`'s input, not by the index it names. Any holder can claim any index, and the caller knows who handed in each position.
- **Public keys:**
  - `encrypt` rejects invalid, non-canonical and small-order recipient keys, so a substituted key such as the ed25519 identity point can't make a share public.
  - `decryptShare` applies the same rules to the ephemeral key in a wrapped share. So anyone who can send a holder envelopes can't use one to probe the holder's ed25519 secret scalar. An encryptor also can't publish a share inside the envelope while its holder's `decryptShare` succeeds, though a dishonest one knows every share and can leak them by other means.
  - Whether each recipient key really belongs to its recipient is the caller's to establish.
- **Recipient privacy:** anyone who has a candidate public key can compute its fingerprint and test whether it is a recipient.
- **No sender authentication:** anyone with the recipients' public keys can create a valid envelope.
- **No revocation:** re-encrypting to a new set of recipients doesn't affect copies of old envelopes.
- **Nonces:** every envelope draws a fresh data key, so a content key never encrypts twice. The nonce is random anyway.
- **Side channels:**
  - The reference implementation uses shamir-secret-sharing 0.0.4. Its GF(2^8) arithmetic looks up log and exp tables at indexes taken from secret bytes, as HashiCorp Vault's does. On shared hardware, that can leak through cache timing.
  - JavaScript gives no general constant-time guarantees.
  - Zeroing memory is best effort in JavaScript.

## Versioning

- **The envelope's version byte** changes only when the layout changes. New suites keep version 1.
- **The share format** has its own version byte.
- **Domain strings** include `v1`, and change with the version.

## Test vectors

The implementation adds two kinds of vectors under `vectors/`:

- known-answer vectors: secret keys, an envelope and `aad`, giving each holder's share and the plaintext;
- byte-exact vectors that build an envelope from a fixed data key, shares, wrapped shares and nonce.

Implementations in other languages check themselves against both.
