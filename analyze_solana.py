#!/usr/bin/env python3
"""Extract the binding a Tinfoil/AMD SEV-SNP chat attestation actually makes.

Reads one or more attestation JSON files (the response of solana.ai's
`/api/chat/attest` or Nito's `/api/v1/attestation`) and reports:

  * the top-level nonce the envelope claims,
  * whether that nonce appears in the signed SEV-SNP report,
  * the 64-byte SEV-SNP report_data field and the two keys it contains.

The report_data layout is Tinfoil's: TLS public-key fingerprint (32 bytes)
followed by the HPKE public key (32 bytes). It is not a per-request challenge.

Usage:
    python3 analyze_solana.py solana/chat-attestation.json runs/nito-attestation.json
"""

from __future__ import annotations

import base64
import gzip
import json
import sys
from pathlib import Path

# AMD SEV-SNP ATTESTATION_REPORT.report_data offset in the 1184-byte report.
REPORT_DATA_OFFSET = 0x50
REPORT_DATA_LEN = 64


def load(path: str) -> tuple[dict, dict]:
    raw = json.loads(Path(path).read_text())
    bundle = raw.get("bundle") or raw.get("evidence", {}).get("bundle")
    if not bundle:
        raise SystemExit(f"{path}: no bundle found")
    return raw, bundle


def decode_report(bundle: dict) -> bytes:
    report = bundle["enclaveAttestationReport"]
    body = base64.b64decode(report["body"])
    return gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body


def main(paths: list[str]) -> int:
    results = []
    for path in paths:
        raw, bundle = load(path)
        nonce = (raw.get("nonce") or "").lower()
        report = decode_report(bundle)
        report_data = report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_LEN]
        nonce_bytes = bytes.fromhex(nonce) if len(nonce) == 64 else b""
        results.append(
            {
                "source": path,
                "model": raw.get("model"),
                "envelope_nonce": nonce,
                "proof_format": raw.get("proof_format"),
                "bundle_digest": bundle.get("digest"),
                "bundle_domain": bundle.get("domain"),
                "report_format": bundle["enclaveAttestationReport"].get("format"),
                "report_bytes": len(report),
                "report_data_hex": report_data.hex(),
                "report_data_halves": {
                    "tls_key_fingerprint": report_data[:32].hex(),
                    "hpke_public_key": report_data[32:].hex(),
                },
                "envelope_nonce_in_signed_report": bool(nonce_bytes)
                and nonce_bytes in report,
                "envelope_nonce_equals_report_data_prefix": bool(nonce_bytes)
                and report_data[:32] == nonce_bytes[:32],
            }
        )
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
