# Application under analysis — exact source revision

The target is the real file-based application from Lab 9A, not a substitute and not an invented upload feature.

| Item | Value |
|---|---|
| Origin repository | `D:\Projects\Lab9A-AES-ECB-GCM` |
| Remote | `https://github.com/incognito-unlimited/Lab9A-AES-ECB-GCM` (private) |
| Analysed commit | `10ec6061cc77ed67f0956ef5938c1227c05efabd` |
| Implementation commit | `54a54ef54131cb9a9acac7298fa7ae99999dba53` |
| Source file | `src/aes_file_demo.py` |
| Source SHA-256 | `2FA3519719348E221B99784AAFFB70DE15AF64AFB67513AA13B9B647AA4FC6C6` |
| Sample input | `samples/repeated_input.txt` |
| Sample SHA-256 | `0E14A4176F1512EE5FC92D73A8602204906CF2118BF565ADC0626908B95F4CBE` |
| Analysis copy | `application/src/aes_file_demo.py` (byte-identical copy; no modifications) |
| Language | Python 3.11.9 |
| Dependency | PyCA `cryptography` 50.0.2 |

## Scope

Analysed: file read/write operations, fixed path derivation, key loading from `LAB9A_AES_KEY_BASE64`, ECB/GCM API usage, padding, tag handling, tampering path, exception handling and the generated execution log.

Excluded: the local `.env` secret, generated ciphertext/decrypted binary artifacts, GitHub credentials, and any functionality not present in the source (there is no HTTP upload endpoint, no filename argument and no native parser).

The copy is included only so SonarQube and Semgrep can scan a stable revision without network access to the private application repository. The hashes above prove the exact revision.
