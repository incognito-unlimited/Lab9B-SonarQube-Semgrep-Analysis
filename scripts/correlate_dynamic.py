#!/usr/bin/env python3
"""Extract genuine Lab 9A dynamic-test excerpts for Lab 9B correlation."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "evidence" / "dynamic-tests" / "lab9a-execution-log.txt"
OUT = ROOT / "evidence" / "dynamic-tests" / "dynamic-correlation.txt"

sections = {}
current = None
for line in LOG.read_text(encoding="utf-8").splitlines():
    if line.startswith("TEST ") or line.startswith("SUMMARY"):
        current = line.strip("= ")
        sections[current] = []
    elif current and line.strip() and not line.startswith("=" * 10):
        sections[current].append(line)

wanted = ["TEST 2 - Structured input and repeated block structure",
          "TEST 3 - AES-ECB encryption (PKCS#7 padding, no IV)",
          "TEST 4 - Repeated ECB ciphertext block identification",
          "TEST 6 - Valid GCM decryption and byte-for-byte comparison",
          "TEST 7 - GCM ciphertext tampering and authentication failure",
          "SUMMARY"]

lines = ["Genuine excerpts from Lab 9A execution-log.txt (copied verbatim; no key values).",
         "Source revision: Lab9A-AES-ECB-GCM @ 10ec6061cc77ed67f0956ef5938c1227c05efabd", ""]
for name in wanted:
    if name not in sections:
        continue
    lines += [f"--- {name} ---"] + sections[name] + [""]
lines += ["GCM tamper rejection is a security-control verification, not a static vulnerability finding.",
          "No dynamic test demonstrated a file-path or upload vulnerability because the application has no such input surface."]
OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("DYNAMIC_CORRELATION_WRITTEN", OUT)
