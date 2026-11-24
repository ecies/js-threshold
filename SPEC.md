# Envelope format, version 1

This is the byte format of `@ecies/threshold` envelopes and shares, and the steps that create and open them. It is a draft until 0.1.0 is released. The design discussion is in [#1](https://github.com/ecies/js-threshold/issues/1).

## Overview

An envelope encrypts a message so that any K of its N recipients, together, can open it.

```text
encrypt(recipients[N], K, plaintext, aad)
  dk       ← 32 random bytes                         the data key
  share_i  ← Shamir split of dk, one per recipient    33 bytes each
  entry_i  ← fingerprint(pk_i) | commitment(share_i) | ECIES(pk_i, share_i)
  header   ← version | suite | K | N | keyCheck(dk) | entry_0 … entry_{N−1}
  content  ← AEAD(contentKey(dk), nonce, header ‖ aad, plaintext)
  return header ‖ content

decryptShare(sk_i, envelope)   → share_i, in the share format below
combine(envelope, K or more shares, aad) → plaintext
```

This is threshold access control, not threshold decryption: `combine` reassembles the data key wherever it runs.

## Conventions

- Lengths are in bytes. Every integer field is one unsigned byte.
- `‖` is concatenation, and `|` separates fields in a layout. `x[a..b]` is bytes `a` up to, not including, `b`.
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

A recipient's canonical public key `pk*` is:

- for secp256k1, the 33-byte compressed SEC1 point, whichever form the caller passed;
- for x25519, the 32-byte public key;
- for ed25519, the 32-byte Ed25519 public key.

```text
fingerprint = SHA-256("ecies-threshold/v1/fingerprint" ‖ pk*)
```

A holder finds their entry by computing their own fingerprint, with no trial decryption. Recipients must be distinct by `pk*`: one person holding two shares would lower the real threshold.

## Envelope

```text
offset        size    field
0             1       version = 0x01
1             1       suite
2             1       threshold K
3             1       recipients N
4             32      key check
36            N × E   recipient entries, E = 64 + W, each:
                        +0    32   fingerprint
                        +32   32   share commitment
                        +64   W    wrapped share
36 + N·E      Ln      nonce            (Ln = the suite's nonce length)
…             16      tag
…             rest    ciphertext
```

- **Header:** the header is the first `H = 36 + N·(64 + W)` bytes, and the content is everything after it.
- **Size:** the envelope is `H + Ln + 16 + |plaintext|` bytes.
  - For example, 2-of-3 with suite `0x01` has 194-byte entries, a 618-byte header and 650 bytes of overhead.
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

- **Recovery:** Lagrange interpolation at 0 over every supplied share, byte by byte. In a field of characteristic 2, subtraction is addition, so:

  ```text
  dk[t] = Σ_j  y_j[t] · Π_{m ≠ j}  x_m / (x_j + x_m)
  ```

## Wrapped shares

```text
wrapped_i = ECIES-Encrypt(pk_i, share_i)
```

This is under the suite's options, as eciesjs 0.5 implements it (see its [DETAILS.md](https://github.com/ecies/js/blob/master/DETAILS.md)). Its layout is `ephemeral public key ‖ nonce ‖ tag ‖ encrypted share`, exactly `W` bytes.

ECIES here takes no associated data, so a wrapped share isn't bound to its envelope directly. The binding comes from its commitment instead:

- the header, commitments included, is the content's associated data;
- each holder checks their share against its commitment.

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
1       16    envelope id = SHA-256("ecies-threshold/v1/envelope-id" ‖ header)[0..16]
17      1     recipient index i, below N
18      33    share_i
```

- **Size:** 51 bytes.
- **Envelope id:** a share from another envelope is reported as such, instead of failing its commitment and blaming its holder.
- **Secrecy:** a share is a secret, since K of them open the envelope. Send it over a confidential channel, for example ECIES-encrypted to the combiner's key.

## Procedures

Errors are named after the conditions below. An implementation can report them in its own way, for example as error classes.

### encrypt(recipients, K, plaintext, aad, config)

1. **Validate the inputs.** Map `config` to a suite. Check 2 ≤ K ≤ N ≤ 255, then compute each recipient's `pk*`. If any of these fails, or two `pk*` are equal: `InvalidArgument`.
2. **Split the data key.** Draw `dk`, split it into N shares with threshold K, and compute each entry.
3. **Build the header.** Compute `keyCheck`, then the header.
4. **Encrypt the content.** Draw the nonce and encrypt the plaintext with `contentKey`.
5. **Zero** `dk`, `contentKey` and the shares, as far as the platform allows.
6. **Return** `header ‖ nonce ‖ tag ‖ ciphertext`.

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
2. **Find the entry.** Derive `pk*` from `sk` on the suite's curve, then find the entry with its fingerprint. If there is none: `NotARecipient`.
3. **Unwrap.** Decrypt the wrapped share with `sk`. If decryption fails: `ShareDecryptionFailed`.
4. **Check the commitment.** If the share doesn't match its commitment: `CommitmentMismatch`. The envelope was altered or built wrong, and this share must not be handed in.
5. **Check the x-coordinate.** If it is 0: `MalformedShare`.
6. **Return** the share in the share format.

### combine(envelope, shares, aad)

1. **Parse** the envelope.
2. **Check each share's format.** For each share, at its position `p`:
   - it is 51 bytes, its version is `0x01`, its index is below N and its x-coordinate isn't 0; otherwise `MalformedShare`;
   - its envelope id matches this envelope's; otherwise `WrongEnvelope`.

   Each error lists every failing position.
3. **Check the indexes.** If two shares have the same index: `DuplicateShare`.
4. **Count.** If there are fewer than K shares: `NotEnoughShares`.
5. **Check the commitments.** If any share doesn't match the commitment of the entry it names: `CommitmentMismatch`, listing every failing position.
6. **Check the x-coordinates.** If two shares have the same x-coordinate: `InconsistentShares`. All the commitments matched, so only the envelope's creator can cause this.
7. **Interpolate** `dk` from every supplied share.
8. **Check the key.** Compare `keyCheck(dk)` with the stored key check in constant time. If they differ: `InconsistentShares`.
9. **Decrypt the content** with `contentKey` and `AD = header ‖ aad`. If decryption fails: `DecryptionFailed`. The `aad` is wrong, or the envelope was altered.
10. **Zero** `dk`, `contentKey` and the share copies, as far as the platform allows. Return the plaintext.

`combine` fails as a whole when any share fails. It doesn't open the envelope with the rest.

To find out who handed in a bad share, the caller drops the named shares and calls `combine` again with others. If the content then opens, the header is as its creator made it. An honest holder's share passed this same commitment at step 4 of `decryptShare`, so the dropped share isn't what its holder's `decryptShare` returned: the holder is dishonest, or the share was altered on its way.

## Security considerations

- **The combiner** learns the data key and the plaintext.
- **Fewer than K shares:** Shamir alone reveals nothing about the data key. The header adds the fingerprints, the commitments and the key check. With K − 1 shares, finding the data key still takes about 2^256 guesses, each checked against the key check.
- **A dishonest encryptor:**
  - **Can't:** make different K-subsets open different plaintexts (the key check), or hand a holder a share that doesn't match its commitment without that holder's `decryptShare` failing.
  - **Can:** make an envelope that some or all K-subsets fail to open (`InconsistentShares`). Nothing authenticates the encryptor (see below).
- **Attribution:** a bad share is reported by its position in `combine`'s input, not by the index it names. Any holder can claim any index, and the caller knows who handed in each position.
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
- byte-exact vectors that build an envelope from a fixed data key, shares, wrapped entries and nonce.

Implementations in other languages check themselves against both.
