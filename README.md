# tee-attestation-audit

Reproducible checks of two "confidential AI" receipts, run on 2026-11-24:

- **NEAR AI Cloud** — request-bound Intel TDX + NVIDIA GPU evidence, verified client-side.
- **Solana Confidential Chat / Nito** — the AMD SEV-SNP enclave bundle the chat page verifies in the browser.

No API keys are required for either run.

## Results

### NEAR AI Cloud (`runs/2026-11-24T1755Z/`, exit 0)

| Check | Result |
|---|---|
| Reports verified with `dcap-qvl` | 5/5 (gateway + 4 model candidates) |
| TCB status / advisories / debug | `UpToDate` / none / off |
| Nonce + signer bound in `report_data` | 5/5 |
| Gateway TLS fingerprint matches the live connection | yes |
| `MRCONFIGID` = `01` + SHA-256(`app_compose`) + 15 zero bytes | 5/5 |
| RTMR3 replay from event log matches the quote | 5/5 |
| NVIDIA NRAS verdict | 4/4 unique GPU payloads `true` |
| Intel Trust Authority token | PS384 signature valid, `UpToDate`, not expired |
| Tamper tests caught | 5/5 |
| Model candidates / measured configs / signing keys | 4 / 3 / 1 |

The ITA token matched the nonce, signer, MRTD, MRSEAM and MRCONFIGID of the
verified quote, but **not** its `report_data` or RTMR3 (`same_quote: false`). It
attests the same image and signer on a different boot/instance, which is the
documented shared-signing-key footgun, not a verification failure.

Artifacts: `report.json` (904 KB raw report), `summary.json`, `nras.json`,
`ita_token.json`, `ita_jwks.json`, `2026-11-24T1755Z.log`.

### Solana chat (`solana/`)

The page's "verified" enclave is Tinfoil's AMD SEV-SNP router, not an on-chain
Solana record.

| Check | Result |
|---|---|
| Bundle verified with the pinned Tinfoil verifier | yes (`@tinfoilsh/verifier` 1.4.0, Sigstore + VCEK chain) |
| Config repo / release | `tinfoilsh/confidential-model-router` / `v0.0.179` |
| Release digest / code measurement | `63ccf36e…dfbc` / `eb59905f…008c` |
| Enclave host / TLS key / HPKE key | `inference.tinfoil.sh` / `901136ba…9926` / `a34169cc…cb6f` |
| Envelope nonce present in the signed report | **no** |
| SEV-SNP `report_data` | TLS key fingerprint ‖ HPKE public key, no challenge |

A second bundle from Nito's own `/api/v1/attestation` (`router-0.tinfoil.sh`)
verified against the same release digest with different TLS/HPKE keys, and its
envelope also echoed a nonce that does not appear in the hardware report.

Artifacts: `chat-attestation.json`, `chat-verification.json`,
`nito-attestation.json`, `nito-verification.json`, `analysis.json`.

## Reproduce

```bash
python3 -m venv .venv
./.venv/bin/pip install dcap-qvl==0.7.1 requests==2.31.0 cryptography==41.0.7
bun add @tinfoilsh/verifier@1.4.0

# NEAR: one random nonce, full hardware + GPU + Intel token + tamper suite.
./.venv/bin/python verify_near.py --outdir runs/$(date -u +%Y-%m-%dT%H%MZ)

# Tinfoil: verify a saved chat attestation bundle offline against the pinned repo.
bun verify_tinfoil.mjs solana/chat-attestation.json solana/chat-verification.json

# Show that the nonce is an envelope field, not part of the hardware report.
python3 analyze_solana.py solana/chat-attestation.json solana/nito-attestation.json
```

`verify_near.py` fetches `https://cloud-api.near.ai/v1/attestation/report` with
`provider=near`, `x-no-aliasing: true`, `include_tls_fingerprint=true` and a
fresh 32-byte nonce; then verifies every returned quote against Intel collateral,
binds the nonce/signer/TLS channel/measured configuration/event log, submits each
unique `nvidia_payload` to `https://nras.attestation.nvidia.com/v3/attest/gpu`,
fetches the Intel Trust Authority token for the same nonce, and re-runs the checks
on mutated copies. Exit code 0 means every real check passed and every mutation
was rejected.

## What the checks do not prove

- That the code inside the TEE is correct or patched. NEAR's 2026-11-08 SGLang
  RCE happened inside an attested, confidential deployment.
- Which instance served a request. NEAR's own docs: instances of the same model
  share one signing key, including instances with different measured
  configurations. `model_attestations[]` is not an inventory.
- That a response came from the instance whose quote you verified, unless you
  check the response signature against exactly one retained report.
- For the Solana chat: that the attestation was made for this request. The
  hardware report binds the enclave's transport keys, not the envelope nonce.
- That the shipping Solana chat consults the on-chain verifier. Its FAQ says it
  does not yet; the verifier program is devnet-only and unaudited.

## Files

```
verify_near.py            NEAR end-to-end verifier + tamper suite
verify_tinfoil.mjs        Offline Tinfoil/Sigstore/SEV-SNP bundle verifier
analyze_solana.py         Extract the SEV-SNP report_data and test nonce binding
runs/2026-11-24T1755Z/    Canonical NEAR run and artifacts
solana/                   Live chat and Nito attestation bundles + verifications
```
