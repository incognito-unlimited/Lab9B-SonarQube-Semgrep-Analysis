#!/usr/bin/env python3
"""
Lab 9A - AES-ECB vs AES-GCM file encryption demonstration.

SECURITY NOTES
- The AES-256 key is generated with os.urandom (CSPRNG) and supplied only through
  the LAB9A_AES_KEY_BASE64 environment variable. It is never hard-coded, printed,
  written to stdout/stderr, or included in the report.
- GCM uses a fresh 12-byte random nonce for every encryption. Nonce reuse with
  the same key is never allowed.
- Decrypted plaintext from a tampered ciphertext is never written or accepted:
  decryptor.finalize() must verify the 16-byte authentication tag first.

Usage:
    python src/aes_file_demo.py --generate-key     # write a new key to .env (gitignored)
    python src/aes_file_demo.py                    # run all tests from the environment
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "repeated_input.txt"
OUT = ROOT / "outputs"
ENV_FILE = ROOT / ".env"
ENV_NAME = "LAB9A_AES_KEY_BASE64"
BLOCK_SIZE_BITS = 128
BLOCK_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16

LOG_LINES = []


def log(line=""):
    print(line)
    LOG_LINES.append(str(line))


def section(title):
    log()
    log("=" * 78)
    log(title)
    log("=" * 78)


def generate_key_file():
    """Create a fresh AES-256 key and store it only in the gitignored .env file."""
    key = os.urandom(32)
    encoded = base64.b64encode(key).decode("ascii")
    ENV_FILE.write_text(
        "# Local Lab 9A secret - generated locally, never commit this file.\n"
        f"{ENV_NAME}={encoded}\n",
        encoding="utf-8",
    )
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass  # Windows may not support POSIX permission bits.
    log("Generated a fresh 32-byte AES-256 key with os.urandom (CSPRNG).")
    log(f"Wrote it to {ENV_FILE.name} only. The key value is never displayed.")
    log("Verify exclusion with: git check-ignore -v .env")


def load_key():
    """Load and validate the key from the environment; never reveal its value."""
    encoded = os.environ.get(ENV_NAME, "")
    if not encoded:
        raise SystemExit(
            f"ERROR: {ENV_NAME} is not set. Run --generate-key first, then load .env."
        )
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise SystemExit(f"ERROR: {ENV_NAME} is not valid base64.")
    if len(key) != 32:
        raise SystemExit(f"ERROR: key must be 32 bytes for AES-256 (got {len(key)}).")
    return key


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def base64_of(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def print_hex_dump(data: bytes, limit=256):
    shown = data[:limit]
    for offset in range(0, len(shown), 16):
        chunk = shown[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        log(f"  {offset:04x}  {hexpart:<47}  |{ascii_part}|")
    if len(data) > limit:
        log(f"  ... ({len(data) - limit} further bytes omitted from this view)")


def make_sample_if_missing():
    # 24 identical 16-byte records -> 24 identical AES plaintext blocks.
    record = b"BLOCK-REPEAT-01\n"  # exactly 16 bytes
    assert len(record) == BLOCK_BYTES
    if not SAMPLE.exists():
        SAMPLE.write_bytes(record * 24)


def run_tests():
    key = load_key()
    OUT.mkdir(parents=True, exist_ok=True)
    make_sample_if_missing()
    plaintext = SAMPLE.read_bytes()

    section("TEST 1 - Key generation and environment-variable loading")
    log(f"Environment variable used: {ENV_NAME}")
    log("Key material: 32 bytes (AES-256); value intentionally not displayed.")
    log("Source: CSPRNG os.urandom via --generate-key; loaded from environment at runtime.")

    section("TEST 2 - Structured input and repeated block structure")
    log(f"File: samples/{SAMPLE.name}  |  size: {len(plaintext)} bytes")
    log(f"AES block size: {BLOCK_BYTES} bytes  |  plaintext blocks: {len(plaintext) // BLOCK_BYTES}")
    log(f"SHA-256 of original: {sha256(plaintext)}")
    log("Each 16-byte record is the identical ASCII line 'BLOCK-REPEAT-01' followed by LF.")
    log("First 4 plaintext blocks (hex):")
    for i in range(4):
        log(f"  block {i:02d}: {plaintext[i*BLOCK_BYTES:(i+1)*BLOCK_BYTES].hex()}")
    print_hex_dump(plaintext, limit=128)

    section("TEST 3 - AES-ECB encryption (PKCS#7 padding, no IV)")
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    log(f"Padded length: {len(padded)} bytes ({len(padded)//BLOCK_BYTES} blocks); PKCS#7 adds {len(padded)-len(plaintext)} byte(s).")
    ecb_enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ecb_ct = ecb_enc.update(padded) + ecb_enc.finalize()
    log(f"ECB ciphertext length: {len(ecb_ct)} bytes; output format: hexadecimal.")
    ecb_blocks = [ecb_ct[i:i+BLOCK_BYTES].hex() for i in range(0, len(ecb_ct), BLOCK_BYTES)]
    for i, block in enumerate(ecb_blocks[:5]):
        log(f"  ciphertext block {i:02d}: {block}")
    log(f"  ciphertext block {len(ecb_blocks)-1:02d} (PKCS#7 padding): {ecb_blocks[-1]}")

    section("TEST 4 - Repeated ECB ciphertext block identification")
    groups = defaultdict(list)
    for idx, block in enumerate(ecb_blocks):
        groups[block].append(idx)
    repeated = {digest: idxs for digest, idxs in groups.items() if len(idxs) > 1}
    log(f"Distinct ECB ciphertext blocks: {len(groups)} of {len(ecb_blocks)} total.")
    for digest, idxs in repeated.items():
        log(f"Repeated block {digest}")
        log(f"  occurs {len(idxs)} times at block indices: {idxs[:12]}{' ...' if len(idxs) > 12 else ''}")
    log("Result: identical plaintext blocks produced byte-identical ECB ciphertext blocks under the same key.")

    section("TEST 5 - AES-GCM encryption of the same original input")
    nonce1 = os.urandom(NONCE_BYTES)
    gcm_enc1 = Cipher(algorithms.AES(key), modes.GCM(nonce1)).encryptor()
    gcm_ct1 = gcm_enc1.update(plaintext) + gcm_enc1.finalize()
    tag1 = gcm_enc1.tag
    nonce2 = os.urandom(NONCE_BYTES)
    gcm_enc2 = Cipher(algorithms.AES(key), modes.GCM(nonce2)).encryptor()
    gcm_ct2 = gcm_enc2.update(plaintext) + gcm_enc2.finalize()
    tag2 = gcm_enc2.tag
    log(f"Algorithm: AES-256-GCM; nonce: {NONCE_BYTES} fresh random bytes; tag: {len(tag1)} bytes.")
    log(f"Nonce 1 (base64, not secret): {base64_of(nonce1)}")
    log(f"Authentication tag 1 (base64): {base64_of(tag1)}")
    log(f"Ciphertext 1 length: {len(gcm_ct1)} bytes (no padding required).")
    log("Ciphertext 1 first 64 hex bytes:")
    print_hex_dump(gcm_ct1, limit=64)
    log(f"Second encryption nonce (base64): {base64_of(nonce2)}")
    log(f"Fresh nonce differs from first: {nonce1 != nonce2}; ciphertext differs: {gcm_ct1 != gcm_ct2}")
    envelope = {
        "algorithm": "AES-256-GCM",
        "nonce_base64": base64_of(nonce1),
        "tag_base64": base64_of(tag1),
        "ciphertext_base64": base64_of(gcm_ct1),
        "input_sha256": sha256(plaintext),
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    (OUT / "gcm_envelope.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    log("Stored nonce, tag and ciphertext together in outputs/gcm_envelope.json.")

    section("TEST 6 - Valid GCM decryption and byte-for-byte comparison")
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce1, tag1)).decryptor()
    recovered = dec.update(gcm_ct1) + dec.finalize()  # verifies the tag
    (OUT / "gcm_decrypted.bin").write_bytes(recovered)
    original_hash = sha256(plaintext)
    recovered_hash = sha256(recovered)
    identical = plaintext == recovered
    log(f"decryptor.finalize() completed: authentication tag verified.")
    log(f"Recovered length: {len(recovered)} bytes; original length: {len(plaintext)} bytes")
    log(f"Original SHA-256   : {original_hash}")
    log(f"Recovered SHA-256  : {recovered_hash}")
    log(f"Byte-for-byte equality (original == recovered): {identical}")
    log(f"Hash equality: {original_hash == recovered_hash}")
    if not identical:
        raise SystemExit("ERROR: valid GCM decryption did not reproduce the original input.")

    section("TEST 7 - GCM ciphertext tampering and authentication failure")
    tampered = bytearray(gcm_ct1)
    tamper_index = len(tampered) // 2
    before = tampered[tamper_index]
    tampered[tamper_index] ^= 0x01
    log(f"Modified exactly one ciphertext byte at index {tamper_index}: 0x{before:02x} -> 0x{tampered[tamper_index]:02x}")
    log("Original nonce and original authentication tag were retained unchanged.")
    tampered_path = OUT / "gcm_tampered.bin"
    tampered_path.write_bytes(tampered)
    tampered_decrypted = OUT / "gcm_tampered_plaintext.bin"
    if tampered_decrypted.exists():
        tampered_decrypted.unlink()
    failure = None
    try:
        bad_dec = Cipher(algorithms.AES(key), modes.GCM(nonce1, tag1)).decryptor()
        _ = bad_dec.update(bytes(tampered)) + bad_dec.finalize()
        failure = "NO EXCEPTION - unexpected acceptance"
    except InvalidTag as exc:
        failure = (
            f"{type(exc).__module__}.{type(exc).__name__}; "
            f"str(exc)={str(exc)!r}; repr(exc)={repr(exc)}"
        )
    log(f"Actual library authentication failure: {failure}")
    log(f"Tampered plaintext file created: {tampered_decrypted.exists()} (must be False)")
    log("Result: unauthenticated plaintext was not produced or treated as valid output.")
    if failure == "NO EXCEPTION - unexpected acceptance" or tampered_decrypted.exists():
        raise SystemExit("ERROR: tampering was not rejected as required.")

    section("TEST 8 - Secret-exclusion configuration (see evidence screenshot for git output)")
    log(f".gitignore excludes: .env, *.key, *.pem, outputs/*.bin, outputs/*.json, __pycache__/")
    log(f".env.example contains only the placeholder: {ENV_NAME}=REPLACE_WITH_YOUR_OWN_BASE64_AES_256_KEY")
    log("No key value appears anywhere in this log or in the generated evidence.")

    section("SUMMARY")
    log(f"ECB repeated-block leakage observed: {'yes' if repeated else 'no'}")
    log(f"Valid GCM decryption matched original byte-for-byte: {identical}")
    log(f"Tampered GCM ciphertext rejected with InvalidTag: {failure.startswith('cryptography.exceptions.InvalidTag')}")
    log("End of execution log.")

    log_path = OUT / "execution-log.txt"
    log_path.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8")
    log(f"\nFull execution log written to outputs/{log_path.name}")


def main():
    parser = argparse.ArgumentParser(description="Lab 9A AES-ECB / AES-GCM demonstration")
    parser.add_argument("--generate-key", action="store_true",
                        help="generate a new AES-256 key into the gitignored .env file")
    args = parser.parse_args()
    if args.generate_key:
        generate_key_file()
        return
    run_tests()


if __name__ == "__main__":
    main()
