# Remediation plan

No remediation was applied to the analysed revision. Therefore no before/after rescan was performed and no fix is claimed. The plan below is proposed from the confirmed findings.

| Priority | Finding(s) | Recommended fix | Owner / status | Retest evidence |
|---|---|---|---|---|
| P1 | F1 (`python:S5542`, ECB rule) | Remove `modes.ECB()` from the encryption path. Use AES-GCM with a fresh random nonce for every encryption, store nonce/tag with ciphertext and call `decryptor.finalize()` before accepting plaintext. Keep ECB only as a clearly labelled non-production teaching example if required. | Proposed; not implemented in the analysed revision. | Not yet available. Regression: repeated plaintext blocks must not repeat in ciphertext; one-byte ciphertext tamper must raise `InvalidTag`; valid decryption must match SHA-256. |
| P2 | F2 (secret `.env` write) | Replace file-based key storage with an OS secret store where available. If a file must be used, set an explicit Windows ACL for current user / Administrators / SYSTEM only, verify it after writing and fail closed on permission errors. Do not silently swallow `OSError`. | Proposed; not implemented in the analysed revision. | Not yet available. Regression: ACL check after key generation must show no `Users` or `Authenticated Users` grant; `.env` must remain Git-ignored; key must never appear in logs or screenshots. |
| P3 | Control assurance (no open scanner finding) | Keep `cryptography` pinned, keep nonce generation from `os.urandom`, keep tag verification and keep generated artifacts excluded from Git. Add the two regression tests above to CI. | Proposed; not implemented. | Lab 9A Tests 6-7 already demonstrate the existing GCM controls; they are not a rescan after fixes. |

## Before/after rescan statement

Because no source changes were made to the analysed revision, a before-and-after scan comparison does not exist. Reporting one would be misleading.
