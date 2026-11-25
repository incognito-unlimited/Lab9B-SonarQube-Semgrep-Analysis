# Source-to-sink traces

## Trace 1 — F1: ECB pattern leakage (confirmed)

| Element | Detail |
|---|---|
| Finding ID / rule | F1 — SonarQube `python:S5542`; Semgrep `config.semgrep.lab9b.python.crypto.ecb-mode` |
| Source of untrusted/data input | `plaintext = SAMPLE.read_bytes()` at `application/src/aes_file_demo.py:123`. The file is `samples/repeated_input.txt`, a fixed local sample when run in the lab; in a real file-encryption application this file content is the untrusted data being protected. It contains 24 identical 16-byte records. |
| Propagation / transformations | `plaintext` -> `padder.update(plaintext) + padder.finalize()` at `:141-142` -> `padded` (400 bytes) -> `ecb_enc.update(padded)` at `:145` -> `ecb_ct` -> block extraction `[ecb_ct[i:i+BLOCK_BYTES].hex() ...]` at `:147` -> `ecb_blocks`. There is validation of block size and PKCS#7 padding, but no randomness or authentication is introduced. |
| Security-sensitive sink | `Cipher(algorithms.AES(key), modes.ECB()).encryptor()` at `:144` and `ecb_enc.update(padded)` at `:145` — cryptographic API misuse with deterministic block mapping. |
| Missing / insufficient control | ECB has no IV/nonce and no authentication tag. Equal plaintext blocks under the same key map to equal ciphertext blocks, leaking equality structure. |
| Dynamic confirmation | Lab 9A Test 4: block `3ed08c28a1dc591f97c16c38ac73f815` repeated 24 times at indices 0-23; 2 distinct blocks of 25. Evidence: `evidence/dynamic-tests/dynamic-correlation.txt`, `lab9a-02-ecb-ciphertext-blocks.png`. |
| Remediation | Remove the ECB encryption path from production use; replace with AES-GCM using a fresh 12-byte nonce per encryption and `decryptor.finalize()` tag verification. Regression test: encrypt an input containing repeated blocks twice and assert that ciphertext differs and that no ciphertext block repeats; assert tampering raises `InvalidTag`. |

## Trace 2 — F2: generated key written to weakly permissioned `.env` (confirmed)

| Element | Detail |
|---|---|
| Finding ID / rule | F2 — Semgrep `config.semgrep.lab9b.python.secret.env-file-write` (CWE-522) |
| Source | `key = os.urandom(32)` at `application/src/aes_file_demo.py:60` and `encoded = base64.b64encode(key)` at `:61`. **Limitation:** this is sensitive locally generated key material, not external untrusted input; the strict “untrusted source” wording is fully met by Trace 1, and this distinction is stated explicitly rather than concealed. The runtime environment variable is another configuration input at `:78`. |
| Propagation / transformations | `ENV_FILE = ROOT / ".env"` at `:36` -> `ENV_FILE.write_text(... f"{ENV_NAME}={encoded}" ...)` at `:62-66` -> `try: ENV_FILE.chmod(0o600) except OSError: pass` at `:67-70`. Later `load_key()` reads `LAB9A_AES_KEY_BASE64` at `:78`, base64-decodes and length-checks it at `:83-88`, and returns it for AES use at `:120`, `:144` and `:165`. |
| Security-sensitive sink | Filesystem write to a predictable `.env` path at `:62`; cryptographic key-use sinks at `:144` (ECB) and `:165` (GCM). |
| Missing / insufficient control | `chmod(0o600)` is best-effort and silently ignored on failure; it does not translate into a restrictive Windows ACL. No OS keystore, explicit DACL or post-write permission verification is performed. |
| Dynamic confirmation | `evidence/dynamic-tests/env-permission-check.txt`: ACL shows `BUILTIN\Users` ReadAndExecute and `NT AUTHORITY\Authenticated Users` Modify on `.env`; `git check-ignore -v .env` confirms `.gitignore:2:.env .env`. The key value was not displayed. |
| Remediation | Prefer Windows DPAPI/Credential Manager or a keyring. If a file is unavoidable, create it with an explicit ACL limited to the current user, Administrators and SYSTEM, verify the ACL after writing, and fail closed instead of swallowing permission errors. Regression test: after key generation, assert the file ACL does not grant `Users` or `Authenticated Users` access and assert the path remains Git-ignored. |

## Honesty note

Two confirmed findings are traced above. Trace 1 is a classic untrusted-input-to-crypto-sink trace. Trace 2 is a sensitive-generated-secret-to-filesystem-sink trace; it is dynamically confirmed but its source is not external untrusted data. It is reported as such rather than being mislabelled.
