#!/usr/bin/env python3
"""Render the article's terminal cards and the cover from the recorded run data.

The JSON bodies are the exact outputs of the commands shown on each card.
Open the generated HTML in the browser and screenshot the #card / #cover node.
"""

from __future__ import annotations

import base64
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
OUT = ROOT / "html"
OUT.mkdir(exist_ok=True)

ACCENT = "#14F195"
BAD = "#ff7b72"
MUTED = "#8b949e"
TEXT = "#d7dde5"

CARD_CSS = """
* { box-sizing: border-box; }
html, body { margin: 0; background: #0b0b0d; }
body { font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace; }
#card { width: 1280px; padding: 40px 42px 34px; background: #0b0b0d; color: %(text)s; }
.window { border: 1px solid #26262c; border-radius: 16px; background: #101114; box-shadow: 0 30px 80px rgba(0,0,0,.55); overflow: hidden; }
.bar { display: flex; align-items: center; gap: 14px; padding: 16px 22px; border-bottom: 1px solid #222229; background: #15161a; }
.dots { display: flex; gap: 8px; }
.dot { width: 11px; height: 11px; border-radius: 50%%; background: #2b2d33; }
.dot.g { background: %(accent)s; }
.label { color: %(muted)s; font-size: 14px; letter-spacing: .04em; }
.host { margin-left: auto; color: #6f7680; font-size: 14px; }
.body { padding: 24px 26px 26px; }
.title { font-family: 'Inter', 'DejaVu Sans', sans-serif; font-size: 17px; font-weight: 600; color: #eef2f6; letter-spacing: -.01em; }
.sub { margin-top: 3px; font-size: 13px; color: %(muted)s; }
.cmd { margin-top: 20px; font-size: 15px; line-height: 1.6; color: #9aa4b2; white-space: pre-wrap; }
.cmd .p { color: %(accent)s; }
.out { margin-top: 16px; border-top: 1px solid #202027; padding-top: 18px; font-size: 15px; line-height: 1.55; }
.line { display: flex; align-items: baseline; gap: 18px; min-height: 25px; }
.line .code { white-space: pre; color: %(text)s; }
.line.ok .code { color: %(accent)s; }
.line.bad .code { color: %(bad)s; }
.line .note { margin-left: auto; padding-left: 16px; color: #6f7680; font-size: 12px; letter-spacing: .02em; }
.line.bad .note { color: #d9908c; }
.rule { height: 1px; background: #202027; margin: 18px 0 14px; }
.foot { display: flex; gap: 18px; align-items: center; color: #6f7680; font-size: 12px; }
.foot .pill { padding: 4px 10px; border: 1px solid #2a2c33; border-radius: 999px; color: #9aa4b2; }
""" % {"text": TEXT, "muted": MUTED, "accent": ACCENT, "bad": BAD}

CARDS = {
    "ita": {
        "title": "NEAR AI Cloud - Intel Trust Authority token",
        "sub": "PS384 token verified against Intel JWKS, cross-checked with the quote this run verified",
        "command": "jq '.checks.ita.cross_checks' runs/2026-11-24T1748Z/summary.json",
        "data": DATA / "ita.json",
        "ok": [
            '"signer_matches": true',
            '"signing_algo_matches": true',
            '"mrtd_matches_quote": true',
            '"mrseam_matches_quote": true',
            '"mrconfigid_matches_quote": true',
            '"caller_nonce_matches": true',
        ],
        "bad": [
            '"report_data_matches_quote": false',
            '"rtmr3_matches_quote": false',
            '"same_quote": false',
        ],
        "notes": {
            '"same_quote": false': "not the quote we verified",
            '"report_data_matches_quote": false': "different boot",
            '"rtmr3_matches_quote": false': "different event log",
        },
        "foot": ["exit 0", "Intel token: valid, UpToDate, unexpired", "2026-11-24 17:48 UTC"],
    },
    "tinfoil": {
        "title": "Solana chat - Tinfoil enclave bundle",
        "sub": "Offline verification of the live chat attestation against the pinned repository",
        "command": "bun verify_tinfoil.mjs solana/chat-attestation.json | jq '{securityVerified: .document.securityVerified, configRepo: .document.configRepo, enclaveHost: .document.enclaveHost, releaseTag: .document.releaseTag, releaseDigest: .document.releaseDigest, codeFingerprint: .document.codeFingerprint, steps: .document.steps}' solana/chat-verification.json",
        "data": DATA / "tinfoil.json",
        "ok": [
            '"securityVerified": true',
            '"releaseTag": "v0.0.179"',
            '"enclaveHost": "inference.tinfoil.sh"',
        ],
        "bad": [],
        "notes": {
            '"securityVerified": true': "Sigstore + VCEK chain",
            '"releaseTag": "v0.0.179"': "pinned repo",
        },
        "foot": ["securityVerified: true", "5/5 verification steps", "2026-11-24 17:45 UTC"],
    },
    "reportdata": {
        "title": "Solana chat - AMD SEV-SNP report_data",
        "sub": "What the hardware report binds, read from offset 0x50 of the signed report",
        "command": "python3 analyze_solana.py solana/chat-attestation.json | jq '.[0] | {source, model, envelope_nonce, bundle_domain, bundle_digest, report_data_halves, envelope_nonce_in_signed_report}'",
        "data": DATA / "reportdata.json",
        "ok": ['"tls_key_fingerprint"', '"hpke_public_key"'],
        "bad": ['"envelope_nonce_in_signed_report": false'],
        "notes": {
            '"envelope_nonce_in_signed_report": false': "nonce not in the report",
            '"tls_key_fingerprint"': "report_data[0:32]",
            '"hpke_public_key"': "report_data[32:64]",
        },
        "foot": ["report_data = TLS || HPKE", "32 + 32 bytes", "2026-11-24 17:45 UTC"],
    },
}


def render_card(key: str, cfg: dict) -> None:
    lines = (cfg["data"]).read_text().rstrip().splitlines()
    out = []
    for line in lines:
        cls = ""
        if any(line.strip().startswith(x) for x in cfg["ok"]):
            cls = "ok"
        if any(line.strip().startswith(x) for x in cfg["bad"]):
            cls = "bad"
        note = next((v for k, v in cfg["notes"].items() if line.strip().startswith(k)), "")
        out.append(
            f'<div class="line {cls}"><span class="code">{html.escape(line)}</span>'
            + (f'<span class="note">{html.escape(note)}</span>' if note else "")
            + "</div>"
        )
    body = f"""<!doctype html><html><head><meta charset="utf-8"><style>{CARD_CSS}</style></head>
<body><div id="card"><div class="window">
<div class="bar"><div class="dots"><span class="dot g"></span><span class="dot"></span><span class="dot"></span></div>
<span class="label">bash</span><span class="host">jvr0x@spark: ~/dev/tee-attestation-audit</span></div>
<div class="body"><div class="title">{html.escape(cfg['title'])}</div><div class="sub">{html.escape(cfg['sub'])}</div>
<div class="cmd"><span class="p">$</span> {html.escape(cfg['command'])}</div>
<div class="out">{''.join(out)}</div>
<div class="rule"></div><div class="foot">{''.join(f'<span class="pill">{html.escape(x)}</span>' for x in cfg['foot'])}</div>
</div></div></div></body></html>"""
    (OUT / f"{key}.html").write_text(body)


def render_cover() -> None:
    shot = base64.b64encode((ROOT / "solana-limitations.png").read_bytes()).decode()
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><style>
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; background: #0b0b0d; }}
body {{ font-family: 'Inter', 'DejaVu Sans', sans-serif; color: #eef2f6; }}
#cover {{ width: 2000px; height: 800px; position: relative; overflow: hidden; background:
  radial-gradient(900px 500px at 8% 0%, rgba(20,241,149,.10), transparent 60%),
  radial-gradient(700px 500px at 95% 100%, rgba(153,69,255,.10), transparent 60%), #0b0b0d; }}
.grid {{ position: absolute; inset: 0; background-image:
  linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
  linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: 64px 64px; mask-image: linear-gradient(180deg, rgba(0,0,0,.9), transparent 75%); }}
.left {{ position: absolute; left: 96px; top: 76px; width: 1180px; }}
.kicker {{ display: inline-flex; align-items: center; gap: 10px; font-family: 'JetBrains Mono', monospace; font-size: 15px; color: #9aa4b2; letter-spacing: .12em; text-transform: uppercase; }}
.kicker b {{ color: #14F195; font-weight: 600; }}
h1 {{ margin: 26px 0 0; font-size: 96px; line-height: 1.02; letter-spacing: -.045em; font-weight: 650; }}
h1 em {{ font-style: normal; color: #14F195; }}
.sub {{ margin-top: 24px; font-size: 34px; line-height: 1.35; color: #b6bec8; letter-spacing: -.015em; }}
.chips {{ display: flex; gap: 14px; margin-top: 46px; flex-wrap: wrap; }}
.chip {{ padding: 14px 20px; border: 1px solid #2a2c33; border-radius: 12px; background: rgba(20,20,23,.72); font-family: 'JetBrains Mono', monospace; font-size: 15px; color: #c7ced7; }}
.chip b {{ color: #14F195; font-weight: 600; }}
.footer {{ position: absolute; left: 98px; bottom: 36px; display: flex; gap: 22px; font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #6f7680; }}
.shot {{ position: absolute; right: 84px; top: 116px; width: 620px; border-radius: 18px; overflow: hidden; border: 1px solid #2a2c33; box-shadow: 0 40px 90px rgba(0,0,0,.65); }}
.shot img {{ width: 100%; display: block; }}
.caption {{ position: absolute; right: 90px; top: 528px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #6f7680; }}
</style></head><body><div id="cover"><div class="grid"></div>
<div class="left"><div class="kicker"><b>VERIFIED</b> TEE ATTESTATION AUDIT / 2026-11-24</div>
<h1>What a TEE Receipt<br>Actually <em>Proves</em></h1>
<div class="sub">NEAR AI Cloud vs Solana Confidential Chat.<br>I verified both from one machine. This is what held.</div>
<div class="chips"><div class="chip"><b>5/5</b> TDX quotes</div><div class="chip"><b>4/4</b> NRAS GPU verdicts</div>
<div class="chip"><b>5/5</b> tamper tests rejected</div><div class="chip">Intel token: <b>different boot</b></div></div></div>
<div class="shot"><img src="data:image/png;base64,{shot}" alt="Solana chat current limitations, live"></div>
<div class="caption">solana.ai/chat - "How it works" - live, 2026-11-24</div>
<div class="footer"><span>javierbits/tee-attestation-audit</span><span>scripts + raw evidence</span></div>
</div></body></html>"""
    (OUT / "cover.html").write_text(html_doc)


def main() -> None:
    for key, cfg in CARDS.items():
        render_card(key, cfg)
    render_cover()
    print("\n".join(str(OUT / f"{k}.html") for k in [*CARDS, "cover"]))


if __name__ == "__main__":
    main()
