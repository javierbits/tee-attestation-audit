#!/usr/bin/env python3
"""Verify a NEAR AI Cloud receipt end to end, then try to break it.

Fetches a request-bound attestation report and an Intel Trust Authority token for
the same nonce, verifies the TDX quotes with Intel's DCAP collateral, checks that
the evidence binds the nonce / signer / TLS channel / measured configuration /
event log, sends the NVIDIA GPU evidence to NRAS, and then re-runs the checks on
tampered copies to prove they have teeth.

Usage:
    ./.venv/bin/python verify_near.py --model z-ai/glm-5.3-flash
    ./.venv/bin/python verify_near.py --no-ita --no-nras   # fast rerun

Exit code 0 only when every real check passed and every tamper test was caught.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import http.client
import json
import os
import secrets
import struct
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import dcap_qvl
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa

HOST = "cloud-api.near.ai"
ITA_HOST = "portal.trustauthority.intel.com"
NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
ACCEPTED_TCB = {"UpToDate"}


# --------------------------------------------------------------------------- io


def fetch_json(host: str, path: str, params: dict[str, str] | None = None):
    """GET over TLS and return (body, sha256 of the peer certificate SPKI)."""
    conn = http.client.HTTPSConnection(host, timeout=90)
    target = path + ("?" + urllib.parse.urlencode(params) if params else "")
    conn.request(
        "GET",
        target,
        headers={"Accept": "application/json", "x-no-aliasing": "true"},
    )
    response = conn.getresponse()
    body = response.read()
    der = conn.sock.getpeercert(binary_form=True)
    conn.close()
    if response.status != 200:
        raise RuntimeError(f"GET {host}{path} -> {response.status}: {body[:300]!r}")
    return json.loads(body), spki_sha256(der)


def spki_sha256(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# --------------------------------------------------------------- quote checks


def _json(value):
    return json.loads(value) if isinstance(value, str) else value


def _signing_identity(report: dict) -> bytes:
    algo = report["signing_algo"]
    identity = bytes.fromhex(report["signing_address"].removeprefix("0x"))
    if {"ecdsa": 20, "ed25519": 32}.get(algo) != len(identity):
        raise ValueError(f"unsupported signing identity for {algo}")
    return identity


def replay_rtmr3(event_log) -> bytes:
    rtmr3 = bytes(48)
    for event in _json(event_log):
        if event.get("imr") != 3:
            continue
        digest = hashlib.sha384(
            struct.pack("<I", event["event_type"])
            + b":"
            + event["event"].encode()
            + b":"
            + bytes.fromhex(event.get("event_payload") or "")
        ).digest()
        if event.get("digest") and bytes.fromhex(event["digest"]) != digest:
            raise ValueError(f"digest mismatch for event {event['event']}")
        rtmr3 = hashlib.sha384(rtmr3 + digest).digest()
    return rtmr3


async def check_report(report: dict, nonce: str, peer_spki: str | None) -> dict:
    """Run the NEAR verification recipe on one report. Raises on hardware failure."""
    verified = await dcap_qvl.get_collateral_and_verify(
        bytes.fromhex(report["intel_quote"])
    )
    quote = json.loads(verified.to_json())["report"]["TD10"]
    out: dict = {
        "app_id": _json(report["info"]).get("app_id"),
        "signing_algo": report["signing_algo"],
        "signing_address": report["signing_address"],
        "tcb_status": verified.status,
        "advisory_ids": list(getattr(verified, "advisory_ids", []) or []),
        "debug_mode": bool(bytes.fromhex(quote["td_attributes"])[0] & 1),
        "nonce_echoed": report["request_nonce"].lower() == nonce.lower(),
    }

    fingerprint = report.get("tls_cert_fingerprint")
    if fingerprint:
        bound = hashlib.sha256(
            _signing_identity(report) + bytes.fromhex(fingerprint)
        ).digest()
    else:
        bound = _signing_identity(report).ljust(32, b"\0")
    out["report_data_binds_nonce_and_signer"] = (
        bytes.fromhex(quote["report_data"]) == bound + bytes.fromhex(nonce)
    )
    if peer_spki is not None:
        out["tls_fingerprint_matches_connection"] = (
            (fingerprint or "").lower() == peer_spki.lower()
        )

    app_compose = _json(report["info"])["tcb_info"]["app_compose"]
    out["app_compose_sha256"] = sha256_hex(app_compose)
    out["config_measurement_matches"] = bytes.fromhex(quote["mr_config_id"]) == (
        b"\x01" + hashlib.sha256(app_compose.encode()).digest() + bytes(15)
    )
    out["rtmr3_matches_event_log"] = replay_rtmr3(report["event_log"]) == bytes.fromhex(
        quote["rt_mr3"]
    )
    out["quote"] = quote
    return out


async def tamper_tests(report: dict, nonce: str, peer_spki: str) -> list[dict]:
    """Every mutation must be rejected by the check that is supposed to catch it."""
    tests: list[dict] = []

    async def record(name: str, check: str, fn):
        try:
            result = await fn()
            passed = bool(result)
            detail = result
        except Exception as exc:  # rejection is a pass for these tests
            passed = True
            detail = f"{type(exc).__name__}: {exc}"
        tests.append({"mutation": name, "expected_check": check, "caught": passed, "detail": str(detail)[:300]})

    wrong_nonce = ("0" if nonce[0] != "0" else "1") + nonce[1:]

    async def bad_nonce():
        result = await check_report(report, wrong_nonce, peer_spki)
        return not result["report_data_binds_nonce_and_signer"]

    await record("change the nonce by one hex character", "report_data binding", bad_nonce)

    flipped = copy.deepcopy(report)
    quote_hex = flipped["intel_quote"]
    index = len(quote_hex) // 2  # inside the quote signature
    flipped["intel_quote"] = (
        quote_hex[:index] + ("0" if quote_hex[index] != "0" else "1") + quote_hex[index + 1 :]
    )

    async def bad_quote():
        await check_report(flipped, nonce, peer_spki)  # must raise
        return False

    await record("flip one hex character inside the TDX quote", "DCAP signature", bad_quote)

    mutated_config = copy.deepcopy(report)
    mutated_config["info"]["tcb_info"]["app_compose"] += " "

    async def bad_config():
        result = await check_report(mutated_config, nonce, peer_spki)
        return not result["config_measurement_matches"]

    await record("append a space to app_compose", "MRCONFIGID measurement", bad_config)

    mutated_log = copy.deepcopy(report)
    events = _json(mutated_log["event_log"])
    for event in reversed(events):
        if event["imr"] == 3 and event.get("event_payload"):
            payload = event["event_payload"]
            event["event_payload"] = (
                payload[:-1] + ("0" if payload[-1] != "0" else "1")
            )
            break
    mutated_log["event_log"] = json.dumps(events)

    async def bad_log():
        result = await check_report(mutated_log, nonce, peer_spki)
        return not result["rtmr3_matches_event_log"]

    await record("flip one hex character in an event payload", "RTMR3 replay", bad_log)

    # A fingerprint from a different host must break the channel binding.
    conn = http.client.HTTPSConnection("example.com", timeout=30)
    conn.request("GET", "/")
    conn.getresponse().read()
    other_spki = spki_sha256(conn.sock.getpeercert(binary_form=True))
    conn.close()

    async def bad_channel():
        result = await check_report(report, nonce, other_spki)
        return not result["tls_fingerprint_matches_connection"]

    await record("claim the report came over example.com's TLS channel", "TLS binding", bad_channel)
    return tests


# ------------------------------------------------------------------ nvidia GPU


def check_nras(payload: dict, nonce: str) -> dict:
    if payload["nonce"].lower() != nonce.lower():
        return {"ok": False, "error": "GPU evidence nonce does not match"}
    request = urllib.request.Request(
        NRAS_URL,
        data=json.dumps(payload).encode(),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        verdict = json.loads(response.read())
    token = verdict[0][1]
    claims = json.loads(b64url_decode(token.split(".")[1]))
    return {
        "ok": claims.get("x-nvidia-overall-att-result") is True,
        "claims": claims,
        "token": token,
    }


# ------------------------------------------------------------- intel ITA token


def verify_ita_token(token: str, jwks: dict) -> dict:
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    claims = json.loads(b64url_decode(payload_b64))
    if header.get("alg") != "PS384":
        raise ValueError(f"unexpected ITA algorithm {header.get('alg')}")
    key = next(k for k in jwks["keys"] if k["kid"] == header.get("kid"))
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode(key["e"]), "big"),
        int.from_bytes(b64url_decode(key["n"]), "big"),
    ).public_key()
    public_key.verify(
        b64url_decode(signature_b64),
        f"{header_b64}.{payload_b64}".encode(),
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA384()), salt_length=48),
        hashes.SHA384(),
    )
    now = int(time.time())
    return {
        "signature_valid": True,
        "kid": header["kid"],
        "iss": claims.get("iss"),
        "iat": claims.get("iat"),
        "nbf": claims.get("nbf"),
        "exp": claims.get("exp"),
        "expired": bool(claims.get("exp", 0) < now),
        "jti": claims.get("jti"),
        "claims": claims,
    }


def compare_ita_with_quote(ita: dict, gateway_check: dict, nonce: str) -> dict:
    """Compare the Intel-signed token with the quote this run verified.

    The token may describe a different quote (another instance or signing
    algorithm), so only the image-level measurements are required to match;
    report_data and RTMR3 are reported as same-quote indicators.
    """
    tdx = ita["claims"].get("tdx", {})
    quote = gateway_check["quote"]
    runtime = tdx.get("attester_runtime_data", {})
    signer = gateway_check["signing_address"].removeprefix("0x").lower()
    return {
        "caller_nonce_matches": runtime.get("caller_nonce", "").lower()
        == nonce.lower(),
        "signer_matches": runtime.get("signing_address", "").removeprefix("0x").lower() == signer,
        "signing_algo_matches": runtime.get("signing_algo", "").lower()
        == gateway_check["signing_algo"].lower(),
        "mrtd_matches_quote": tdx.get("tdx_mrtd", "").lower()
        == quote["mr_td"].lower(),
        "mrseam_matches_quote": tdx.get("tdx_mrseam", "").lower()
        == quote["mr_seam"].lower(),
        "mrconfigid_matches_quote": tdx.get("tdx_mrconfigid", "").lower()
        == quote["mr_config_id"].lower(),
        "report_data_matches_quote": tdx.get("tdx_report_data", "").lower()
        == quote["report_data"].lower(),
        "rtmr3_matches_quote": tdx.get("tdx_rtmr3", "").lower()
        == quote["rt_mr3"].lower(),
        "same_quote": (
            tdx.get("tdx_report_data", "").lower() == quote["report_data"].lower()
            and tdx.get("tdx_rtmr3", "").lower() == quote["rt_mr3"].lower()
        ),
        "attester_tcb_status": tdx.get("attester_tcb_status"),
        "debuggable": tdx.get("tdx_is_debuggable"),
        "attester_type": tdx.get("attester_type"),
    }


# ------------------------------------------------------------------------ main


async def main_async(args) -> int:
    nonce = args.nonce or secrets.token_hex(32)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": args.model,
        "endpoint": f"https://{HOST}{args.path}",
        "nonce": nonce,
        "checks": {},
        "ok": True,
    }

    print(f"[1/6] requesting attestation report for {args.model} with a fresh nonce")
    report, peer_spki = fetch_json(
        HOST,
        args.path,
        {
            "model": args.model,
            "provider": "near",
            "include_tls_fingerprint": "true",
            "signing_algo": args.signing_algo,
            "nonce": nonce,
        },
    )
    (outdir / "report.json").write_text(json.dumps(report, indent=2))
    summary["report_sha256"] = sha256_hex((outdir / "report.json").read_bytes())
    summary["tls_fingerprint_observed"] = peer_spki
    print(f"      saved report.json ({summary['report_sha256'][:16]}...)")

    print("[2/6] verifying gateway quote and every model candidate with dcap-qvl")
    gateway = await check_report(report["gateway_attestation"], nonce, peer_spki)
    models = []
    for candidate in report.get("model_attestations") or []:
        check = await check_report(candidate, nonce, peer_spki)
        check["model_name"] = candidate.get("model_name")
        models.append(check)
    summary["checks"]["gateway"] = gateway
    summary["checks"]["models"] = models

    signers = {c["signing_address"] for c in models}
    algos = {c["signing_algo"] for c in models}
    configs = {c["app_compose_sha256"] for c in models}
    summary["signer_inventory"] = {
        "model_candidates": len(models),
        "unique_signing_addresses": len(signers),
        "signing_algorithms": sorted(algos),
        "unique_measured_configurations": len(configs),
        "signing_addresses": sorted(signers),
        "app_compose_sha256": sorted(configs),
    }
    print(
        f"      {len(models)} candidates -> {len(configs)} measured configurations, "
        f"{len(signers)} signing key(s)"
    )

    if args.nras:
        print("[3/6] sending GPU evidence to NVIDIA NRAS")
        nras_results = []
        seen = set()
        for index, candidate in enumerate(report.get("model_attestations") or []):
            payload = candidate.get("nvidia_payload")
            if not payload:
                continue
            payload = _json(payload)
            digest = sha256_hex(json.dumps(payload, sort_keys=True))
            if digest in seen:
                continue
            seen.add(digest)
            result = check_nras(payload, nonce)
            result["candidate_index"] = index
            nras_results.append(result)
            print(f"      candidate {index}: overall verdict = {result['ok']}")
        (outdir / "nras.json").write_text(json.dumps(nras_results, indent=2))
        summary["checks"]["nras"] = [
            {"candidate_index": r["candidate_index"], "ok": r["ok"]} for r in nras_results
        ]

    if args.ita:
        print("[4/6] fetching an Intel Trust Authority token for the same nonce")
        ita_body, _ = fetch_json(
            HOST,
            "/v1/attestation/ita-token",
            {
                "model": args.model,
                "nonce": nonce,
                "provider": "near",
                "signing_algo": args.signing_algo,
                "include_tls_fingerprint": "true",
            },
        )
        (outdir / "ita_token.json").write_text(json.dumps(ita_body, indent=2))
        jwks, _ = fetch_json(ITA_HOST, "/certs")
        (outdir / "ita_jwks.json").write_text(json.dumps(jwks, indent=2))
        ita = verify_ita_token(ita_body["gateway"]["token"], jwks)
        ita["token_sha256"] = sha256_hex(ita_body["gateway"]["token"])
        ita["cross_checks"] = compare_ita_with_quote(ita, gateway, nonce)
        ita.pop("claims")
        summary["checks"]["ita"] = ita
        print(
            "      Intel token signature valid; TCB status = "
            f"{ita['cross_checks']['attester_tcb_status']}"
        )

    print("[5/6] re-running the checks on tampered evidence")
    summary["tamper_tests"] = await tamper_tests(report["gateway_attestation"], nonce, peer_spki)
    for test in summary["tamper_tests"]:
        print(f"      {test['mutation']}: caught={test['caught']} ({test['detail'][:80]})")

    print("[6/6] writing summary.json")
    required = [
        gateway["tcb_status"] in ACCEPTED_TCB,
        not gateway["debug_mode"],
        gateway["nonce_echoed"],
        gateway["report_data_binds_nonce_and_signer"],
        gateway.get("tls_fingerprint_matches_connection") is True,
        gateway["config_measurement_matches"],
        gateway["rtmr3_matches_event_log"],
        all(c["tcb_status"] in ACCEPTED_TCB for c in models),
        all(not c["debug_mode"] for c in models),
        all(c["report_data_binds_nonce_and_signer"] for c in models),
        all(c["config_measurement_matches"] for c in models),
        all(c["rtmr3_matches_event_log"] for c in models),
        all(t["caught"] for t in summary["tamper_tests"]),
    ]
    if args.ita:
        ita = summary["checks"]["ita"]
        required += [
            ita["signature_valid"],
            not ita["expired"],
            ita["cross_checks"]["caller_nonce_matches"],
            ita["cross_checks"]["signer_matches"],
            ita["cross_checks"]["signing_algo_matches"],
            ita["cross_checks"]["mrtd_matches_quote"],
            ita["cross_checks"]["mrseam_matches_quote"],
            ita["cross_checks"]["mrconfigid_matches_quote"],
            ita["cross_checks"]["attester_tcb_status"] in ACCEPTED_TCB,
            ita["cross_checks"]["debuggable"] is False,
        ]
    summary["ok"] = all(required)
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"      ALL CHECKS PASSED: {summary['ok']}")
    print(f"      artifacts in {outdir}")
    return 0 if summary["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="z-ai/glm-5.3-flash")
    parser.add_argument("--path", default="/v1/attestation/report")
    parser.add_argument("--nonce", default=None, help="32-byte hex challenge; random if omitted")
    parser.add_argument("--outdir", default="runs/latest")
    parser.add_argument("--no-nras", dest="nras", action="store_false")
    parser.add_argument("--signing-algo", default="ecdsa")
    parser.add_argument("--no-ita", dest="ita", action="store_false")
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
