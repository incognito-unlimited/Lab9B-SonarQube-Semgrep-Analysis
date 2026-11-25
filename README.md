# Lab 9B — Source Code Static Analysis with SonarQube and Semgrep

**Student:** Aditey Mehra | **Roll:** 2301730266 | B.Tech CSE (AI & ML), Section D, Semester 7 | K.R. Mangalam University
**Subject:** Secure Coding and Vulnerabilities | Lab 9B, Experiment 20

## Aim

Perform static analysis on the real file-based application from Lab 9A, triage findings by severity and confidence, correlate them with genuine dynamic-test evidence, trace confirmed findings from source to sink, and submit reproducible configuration and sanitized evidence.

## Application under analysis

The target is the Lab 9A AES-256 file-encryption/decryption program, not a substitute and not an invented upload application.

- Origin: `https://github.com/incognito-unlimited/Lab9A-AES-ECB-GCM` (private), local path `D:\Projects\Lab9A-AES-ECB-GCM`
- Analysed commit: `10ec6061cc77ed67f0956ef5938c1227c05efabd`
- Implementation commit: `54a54ef54131cb9a9acac7298fa7ae99999dba53`
- Analysed file: `application/src/aes_file_demo.py` — byte-identical copy, SHA-256 `2FA3519719348E221B99784AAFFB70DE15AF64AFB67513AA13B9B647AA4FC6C6`
- Sample: `application/samples/repeated_input.txt` — 384 bytes, 24 identical 16-byte records, SHA-256 `0E14A4176F1512EE5FC92D73A8602204906CF2118BF565ADC0626908B95F4CBE`
- Scope: file read/write, fixed path derivation, key generation/loading, ECB/GCM API usage, padding, tag verification, tampering path, exception handling and generated logs
- Excluded: no HTTP upload, no user-supplied filename argument, no parser/deserialiser, no native C/C++ component

Provenance is recorded in `application/SOURCE_REVISION.md`.

## Environment

- Operating system: Windows 11 Home Single Language, build `10.0.26300`
- Python: `3.11.9`
- Docker Desktop with Linux engine `29.9.2`
- SonarQube Community Edition: `26.11.0.134175`, server ID `147B411E-AaITVNbE5akTbNds9Oll`
- SonarScanner CLI: `8.5.0.16571` (image `sonarsource/sonar-scanner-cli:latest`)
- Semgrep CLI: `1.187.0`

## Setup

```powershell
python -m pip install -r requirements.txt
```

Start SonarQube locally:

```powershell
docker run -d --name lab9b-sonarqube -p 9000:9000 `
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true `
  -e SONARQUBE_JAVA_OPTS='-Xms1g -Xmx1g' sonarqube:community
```

Wait until `http://127.0.0.1:9000/api/system/status` reports `UP`. Create the project once via `POST /api/projects/create?project=lab9b-aes-file-demo&name=Lab%209B%20AES%20file%20demo`.

## Reproducible scan commands

### SonarQube

Configuration: `config/sonar-project.properties` — project key `lab9b-aes-file-demo`, source `application/src`, Python 3.11, UTF-8, SCM disabled, quality profile `Sonar way core`.

Generate a token through SonarQube's API or UI and keep it only in a local secret store. Never commit it.

```powershell
$env:SONAR_TOKEN = <local token read from a file outside this repository>
$env:SONAR_HOST_URL = 'http://host.docker.internal:9000'
docker run --rm -e SONAR_HOST_URL -e SONAR_TOKEN `
  -v "<repo>:/usr/src" -w /usr/src sonarsource/sonar-scanner-cli:latest `
  "-Dproject.settings=/usr/src/config/sonar-project.properties"

$env:SONAR_HOST_URL = 'http://127.0.0.1:9000'
python scripts/sonar_evidence.py
```

The evidence collector stores only sanitized API JSON/text; the token is never written to disk. Exact versions and commands are also in `reports/scan-commands.txt`.

### Semgrep

Rulesets: Semgrep Registry `p/python` plus repository custom rules in `config/semgrep/python-security.yml` (ECB mode and predictable secret-file write).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/semgrep_scan.ps1
```

Outputs: `evidence/semgrep/semgrep.json` and `evidence/semgrep/semgrep.txt`.

### Dynamic correlation

```powershell
python scripts/correlate_dynamic.py
```

This extracts exact excerpts from the copied Lab 9A execution log. `evidence/dynamic-tests/env-permission-check.txt` records a controlled Windows ACL/git-ignore check on the local gitignored `.env`; the key value is intentionally omitted.

## Findings summary

| ID | Tool / rule | Location | Severity | Confidence | Triage |
|---|---|---|---|---|---|
| F1 | SonarQube `python:S5542`; Semgrep `config.semgrep.lab9b.python.crypto.ecb-mode` | `application/src/aes_file_demo.py:144` | High | High | Confirmed by dynamic testing — 24 identical ECB ciphertext blocks |
| F2 | Semgrep `config.semgrep.lab9b.python.secret.env-file-write` | `application/src/aes_file_demo.py:36,60-70` | Medium | High for observed ACL; Medium for remote exploitability | Confirmed local permission weakness — Windows ACL grants broad access to `.env` |

SonarQube measured 207 ncloc, 1 vulnerability, 0 hotspots, 0 bugs and 0 code smells. Semgrep ran 153 rules on 1 file with 0 errors and 2 findings. Full triage is in `reports/findings-register.md`.

## Dynamic cross-reference

- **F1 — confirmed:** Lab 9A Tests 2-4 observed 24 identical ciphertext blocks from 24 identical plaintext blocks.
- **F2 — confirmed:** Controlled ACL check showed `BUILTIN\Users` ReadAndExecute and `NT AUTHORITY\Authenticated Users` Modify on the gitignored `.env` file.
- **Control verified, not a finding:** Lab 9A Tests 5-7 showed valid GCM decryption and `InvalidTag` rejection of a one-byte ciphertext tamper. This is not used to confirm an unrelated static alert.

See `reports/dynamic-correlation.md`.

## Source-to-sink traces

1. **F1 (confirmed):** `SAMPLE.read_bytes()` (`:123`) → `padded` (`:141-142`) → `Cipher(..., modes.ECB())` (`:144`) → `ecb_ct`/`ecb_blocks` (`:145-147`). Dynamic confirmation: repeated ciphertext block at 24 indices.
2. **F2 (confirmed):** `os.urandom(32)` (`:60`) → base64 (`:61`) → `ENV_FILE.write_text` (`:62-66`) → ineffective `chmod` (`:67-70`) → environment load (`:78-88`) → AES sinks (`:144`, `:165`). The source is sensitive generated key material, not external untrusted input; this limitation is stated explicitly.

Full details and regression tests are in `reports/source-to-sink-traces.md`.

## Native parser testing

Not applicable. The target is Python-only and contains no native C/C++ parser under assessment. No Radamsa, zzuf, Valgrind or AddressSanitizer testing was performed or claimed.

## Remediation

Proposed only; no source fix was applied to the analysed revision, so no before/after rescan exists. See `reports/remediation-plan.md`.

## Evidence

- `evidence/sonarqube/` — API summary, issues, hotspots, measures, quality profile, rule detail, scanner log and screenshots
- `evidence/semgrep/` — JSON/text findings and screenshot
- `evidence/dynamic-tests/` — genuine Lab 9A log, screenshots, extracted correlation and permission check
- `evidence/source-to-sink/` — exact code excerpts and trace screenshots
- `evidence/remediation.png` — proposed fixes and explicit no-rescan statement
- `reports/` — findings register, correlation, traces, remediation plan and exact commands

No scanner token, AES key, credential or generated ciphertext/decrypted plaintext is committed.

## GitHub submission

Private repository: https://github.com/incognito-unlimited/Lab9B-SonarQube-Semgrep-Analysis
