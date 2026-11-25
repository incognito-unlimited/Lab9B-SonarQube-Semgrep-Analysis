# Consolidated findings register

Two distinct material findings were reported across both tools. SonarQube reported one additional security-relevant issue and no hotspots, bugs or code smells. Semgrep reported the same ECB issue via a custom rule plus one secret-file-handling issue. Severity and confidence are recorded separately; neither is inferred from the other.

| ID | Tool and rule ID | File and line | Description | Severity | Confidence | Triage / status | Recommended action |
|---|---|---|---|---|---|---|---|
| F1 (S1) | SonarQube `python:S5542` (VULNERABILITY, CRITICAL, impact SECURITY=HIGH); Semgrep `config.semgrep.lab9b.python.crypto.ecb-mode` (WARNING) | `application/src/aes_file_demo.py:144` (`modes.ECB()`), with block extraction at `:145-147` | AES-ECB is used to encrypt file content. ECB encrypts 16-byte blocks independently and deterministically, so equal plaintext blocks produce equal ciphertext blocks. The ECB path also has no authentication tag. | High (manual rating; scanner rated Critical because the rule treats ECB as a critical cryptographic misuse) | High | **(a) Confirmed by dynamic testing.** Lab 9A Tests 3-4 observed 24 identical ciphertext blocks from 24 identical plaintext blocks. | Remove ECB from any real encryption path. Use AES-GCM with a fresh nonce and verify the tag. If ECB is retained only as a classroom demonstration, label it as non-production and never use it on real data. |
| F2 (S2) | Semgrep `config.semgrep.lab9b.python.secret.env-file-write` (WARNING; metadata CWE-522). SonarQube reported no hotspot for this path. | `application/src/aes_file_demo.py:36,60-70` (`.env` path, generated key, `write_text`, best-effort `chmod(0o600)`) | A generated AES-256 key is written to a predictable local `.env` file. The POSIX `chmod(0o600)` call is wrapped in `except OSError: pass`, and on Windows it does not create a restrictive ACL. | Medium (local-only; requires a local account or access to backups/sync) | High for the observed ACL; Medium for remote exploitability (there is no remote exposure in this application) | **(a) Confirmed by dynamic testing** for the local permission weakness. The controlled ACL check showed `BUILTIN\Users` ReadAndExecute and `NT AUTHORITY\Authenticated Users` Modify on `.env`, while Git correctly ignores the file. | Use an OS secret store (Windows DPAPI/Credential Manager or a keyring) where available. If a file must be used, set an explicit Windows ACL granting only the current user, Administrators and SYSTEM, and fail closed when restrictive permissions cannot be applied. Keep `.env` gitignored. |

## Filtering and non-findings

- SonarQube measures: 207 ncloc, 1 vulnerability, 0 security hotspots, 0 bugs, 0 code smells. No hotspot or code-smell triage rows are required.
- Semgrep scanned one Python file with 153 rules and produced exactly two findings, both retained above.
- The GCM nonce/tag representation and the `InvalidTag` rejection in Lab 9A are **security controls working correctly**, not vulnerabilities. They are not counted as findings.
- No filename/path traversal, upload, parser or deserialisation finding is reported because those input surfaces do not exist in the analysed source.

## Severity versus confidence

- F1 is high severity and high confidence: both scanners, the source code and the dynamic output agree.
- F2 is medium severity because exploitation needs local access, but high confidence for the observed ACL weakness; the broader threat model remains medium confidence because the application has no remote interface.
