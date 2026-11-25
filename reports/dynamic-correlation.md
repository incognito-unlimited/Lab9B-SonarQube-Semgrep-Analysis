# Dynamic-testing cross-reference

Dynamic evidence is genuine Lab 9A output copied from the exact analysed revision. The extracted excerpts are in `evidence/dynamic-tests/dynamic-correlation.txt`; full log is `evidence/dynamic-tests/lab9a-execution-log.txt`; screenshots are `evidence/dynamic-tests/lab9a-*.png`.

| Static finding | Related dynamic test / payload | Observed dynamic result | Classification | Justification / evidence |
|---|---|---|---|---|
| F1 — SonarQube `python:S5542`, Semgrep ECB rule | Lab 9A Test 2-4; safe synthetic input `samples/repeated_input.txt`, 384 bytes = 24 identical 16-byte records `BLOCK-REPEAT-01\n` | ECB padded input to 400 bytes / 25 blocks; ciphertext block `3ed08c28a1dc591f97c16c38ac73f815` occurred 24 times at indices 0-23; only 2 distinct ciphertext blocks of 25. | **(a) Confirmed** | The dynamic test demonstrates exactly the deterministic block equality that the ECB rule warns about. Figure 8.1a/8.1b in Lab 9A and the extracted log lines show the observation. |
| F2 — Semgrep secret-file write | Controlled local ACL/git check on the gitignored Lab 9A `.env` (`evidence/dynamic-tests/env-permission-check.txt`); no key value displayed | `.env` exists; ACL grants `BUILTIN\Users` ReadAndExecute and `NT AUTHORITY\Authenticated Users` Modify; `git check-ignore -v .env` returned `.gitignore:2:.env .env`. | **(a) Confirmed** for local permission weakness | The observed ACL shows that `chmod(0o600)` did not restrict access on Windows. The file is excluded from Git, so no repository disclosure occurred; the weakness is local at-rest protection, not secret commit. |
| No static finding (control verification) | Lab 9A Tests 5-7; GCM valid decryption and one-byte ciphertext tamper at index 192 (`0xc5 → 0xc4`) with original nonce/tag retained | Valid decryption returned `original == recovered = True` with matching SHA-256. Tampered decryption raised `cryptography.exceptions.InvalidTag`; no tampered plaintext file was created. | Not a finding — control verified | This is a positive security-control observation. No scanner reported a GCM weakness, and the dynamic test does not demonstrate a vulnerability. It is deliberately not used to confirm an unrelated static alert. |

## Interpretation limits

- No dynamic test was performed for path traversal, upload filtering, deserialisation or command injection because the application has none of those surfaces.
- The ECB dynamic observation is a cryptographic behaviour demonstration, but here it directly corresponds to the static rule at line 144; therefore it is a valid confirmation for F1.
- The GCM tamper rejection is not treated as confirmation of any static finding.
