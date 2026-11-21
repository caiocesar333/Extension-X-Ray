from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .models import Confidence, Finding, FindingEvidence, Severity, SourceLocation

_MNEMONIC_ASSIGNMENT = re.compile(
    r"\b(?:seedPhrase|seed_phrase|mnemonic|recoveryPhrase)\b\s*[:=]\s*['\"]([^'\"\r\n]{40,500})['\"]",
    re.IGNORECASE,
)
_MNEMONIC_WORD_COUNTS = {12, 15, 18, 21, 24}
_MNEMONIC_WORD = re.compile(r"[A-Za-z]{2,16}")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_ENCODED_SECRET = re.compile(
    r"\b(?:privateKey|private_key|secretKey|secret_key|walletKey|wallet_key)\b\s*[:=]\s*"
    r"(['\"])(?:0x)?(?:[a-fA-F0-9]{64}|[1-9A-HJ-NP-Za-km-z]{80,120})\1",
    re.IGNORECASE,
)
_CRYPTO_ENV = re.compile(
    r"(?:process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[['\"]([^'\"]+)['\"]\])|"
    r"Deno\.env\.get\(['\"]([^'\"]+)['\"]\)|"
    r"os\.environ(?:\[['\"]([^'\"]+)['\"]\]|\.get\(['\"]([^'\"]+)['\"]\))|"
    r"os\.getenv\(['\"]([^'\"]+)['\"]\))",
)
_CRYPTO_ENV_NAME = re.compile(
    r"(?:PRIVATE[_-]?KEY|SECRET[_-]?KEY|SEED(?:[_-]?PHRASE)?|MNEMONIC|RECOVERY[_-]?PHRASE|WALLET[_-]?(?:KEY|SECRET))",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]+)",
    re.MULTILINE,
)
_NETWORK_CALL = re.compile(
    r"\b(?:fetch|WebSocket|axios\s*\.\s*(?:get|post|put|patch|request)|"
    r"(?:https?|client|requests|httpx)\s*\.\s*(?:get|post|put|patch|request)|"
    r"urllib\.request\.urlopen|[A-Za-z_$][\w$]*\s*\.\s*send)\s*\(",
    re.IGNORECASE,
)
_PROCESS_CALL = re.compile(
    r"\b(?:(?:(?:child_process|cp)\s*\.\s*)?(?:exec|execFile|spawn|fork|execSync|spawnSync)|"
    r"subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output)|os\s*\.\s*system)\s*\(",
)
_CLIPBOARD_READ = re.compile(r"(?:clipboard\s*\.\s*readText|readClipboard|Get-Clipboard|pyperclip\.paste)\s*\(?", re.IGNORECASE)
_CLIPBOARD_WRITE = re.compile(r"(?:clipboard\s*\.\s*writeText|writeClipboard|Set-Clipboard|pyperclip\.copy)\s*\(?", re.IGNORECASE)
_CRYPTO_ADDRESS = re.compile(
    r"(?:\b0x[a-fA-F0-9]{40}\b|\bbc1[a-zA-HJ-NP-Z0-9]{20,90}\b|"
    r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b[1-9A-HJ-NP-Za-km-z]{32,44}\b)"
)

_WALLET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Bitcoin", re.compile(r"(?:^|[/\\])\.bitcoin[/\\](?:wallets?[/\\])?wallet\.dat\b|\bwallet\.dat\b", re.IGNORECASE)),
    ("Ethereum", re.compile(r"(?:^|[/\\])\.ethereum(?:[/\\]|['\"])|(?:^|[/\\])keystore(?:[/\\]|['\"])", re.IGNORECASE)),
    ("Solana", re.compile(r"(?:^|[/\\])\.config[/\\]solana[/\\]id\.json\b", re.IGNORECASE)),
    ("Electrum", re.compile(r"(?:^|[/\\])\.electrum[/\\]wallets(?:[/\\]|['\"])", re.IGNORECASE)),
    ("Exodus", re.compile(r"(?:^|[/\\])Exodus[/\\]exodus\.wallet\b|\bexodus\.wallet\b", re.IGNORECASE)),
    ("Atomic Wallet", re.compile(r"(?:^|[/\\])atomic(?:[/\\].*)?[/\\]Local Storage(?:[/\\]|['\"])", re.IGNORECASE)),
    (
        "browser wallet extension",
        re.compile(
            r"Local Extension Settings[/\\](?:"
            r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|"
            r"hnfanknocfeofbddgcijnmhnfnkdnaad|fhbohimaelbohpjbbldcngcnapndodjp|"
            r"acmacodkjbdgmoleebolmdjonilkdbch|bhhhlbepdkbapadjdnnojkbgioiodbic)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class _WalletMatch:
    family: str
    match: re.Match[str]


def _line_details(text: str, offset: int) -> tuple[int, int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return line, offset - start + 1, text[start:end].strip().replace("\x00", "")[:320]


def _mnemonic_assignment(text: str) -> re.Match[str] | None:
    for match in _MNEMONIC_ASSIGNMENT.finditer(text):
        words = match.group(1).split()
        if len(words) in _MNEMONIC_WORD_COUNTS and all(
            _MNEMONIC_WORD.fullmatch(word) for word in words
        ):
            return match
    return None


def _wallet_matches(text: str) -> list[_WalletMatch]:
    matches: list[_WalletMatch] = []
    for family, pattern in _WALLET_PATTERNS:
        if match := pattern.search(text):
            matches.append(_WalletMatch(family=family, match=match))
    return matches


def _crypto_env_match(text: str) -> re.Match[str] | None:
    for match in _CRYPTO_ENV.finditer(text):
        name = next((group for group in match.groups() if group), "")
        if _CRYPTO_ENV_NAME.search(name):
            return match
    return None


def _contains_sensitive_source(text: str) -> bool:
    return bool(
        _PRIVATE_KEY.search(text)
        or _mnemonic_assignment(text)
        or _ENCODED_SECRET.search(text)
        or _wallet_matches(text)
        or _crypto_env_match(text)
    )


def redact_sensitive_evidence(snippet: str) -> str:
    if (
        _PRIVATE_KEY.search(snippet)
        or _MNEMONIC_ASSIGNMENT.search(snippet)
        or _ENCODED_SECRET.search(snippet)
    ):
        return "[REDACTED: possible private wallet material]"
    return snippet


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    impact: str,
    guidance: str,
    path: str,
    text: str,
    offset: int,
    tags: tuple[str, ...],
    summary: str,
) -> Finding:
    line, column, snippet = _line_details(text, offset)
    safe_snippet = redact_sensitive_evidence(snippet)
    digest = hashlib.sha256(f"{rule_id}:{path}:{line}:{safe_snippet}".encode()).hexdigest()[:16]
    return Finding(
        id=f"finding-{digest}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=FindingEvidence(summary=summary, snippet=safe_snippet),
        location=SourceLocation(file=path, line=line, column=column),
        potential_impact=impact,
        guidance=guidance,
        tags=list(tags),
        source="crypto-guard",
    )


def _identifier_in(text: str, identifier: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(identifier)}(?![\w$])", text) is not None


def _assignments(text: str) -> list[tuple[str, str, int]]:
    return [(match.group(1), match.group(2), match.start()) for match in _ASSIGNMENT.finditer(text)]


def _propagate_variables(
    assignments: list[tuple[str, str, int]],
    initial: set[str],
) -> set[str]:
    tracked = set(initial)
    for _ in range(4):
        added = {
            name
            for name, expression, _offset in assignments
            if name not in tracked and any(_identifier_in(expression, source) for source in tracked)
        }
        if not added:
            break
        tracked.update(added)
    return tracked


def _balanced_call(text: str, start: int, maximum: int = 4_000) -> str:
    opening = text.find("(", start, min(len(text), start + 300))
    if opening == -1:
        end = text.find("\n", start)
        return text[start:len(text) if end == -1 else end]
    depth = 0
    quote: str | None = None
    escaped = False
    end_limit = min(len(text), opening + maximum)
    for index in range(opening, end_limit):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:end_limit]


def _tainted_call(
    text: str,
    pattern: re.Pattern[str],
    tainted: set[str],
) -> tuple[int, str, list[str]] | None:
    for match in pattern.finditer(text):
        call = _balanced_call(text, match.start())
        used = sorted(name for name in tainted if _identifier_in(call, name))
        if used or _contains_sensitive_source(call):
            return match.start(), call, used
    return None


def _address_variables(assignments: list[tuple[str, str, int]]) -> set[str]:
    initial = {name for name, expression, _offset in assignments if _CRYPTO_ADDRESS.search(expression)}
    return _propagate_variables(assignments, initial)


def scan_crypto_file(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    private_key = _PRIVATE_KEY.search(text)
    mnemonic = _mnemonic_assignment(text)
    encoded_secret = _ENCODED_SECRET.search(text)
    wallet_matches = _wallet_matches(text)
    crypto_env = _crypto_env_match(text)

    if private_key or mnemonic:
        match = private_key or mnemonic
        assert match is not None
        findings.append(_finding(
            rule_id="CRYPTO-SECRET-001",
            title="Possible private wallet material in repository",
            severity=Severity.critical,
            confidence=Confidence.high if private_key else Confidence.medium,
            description="The source contains a private-key marker or a recovery-phrase-like assignment.",
            impact="Anyone with repository access may be able to control the associated assets.",
            guidance="Assume exposed material is compromised, move assets to a new wallet, and remove it from repository history.",
            path=path, text=text, offset=match.start(), tags=("crypto", "secret", "wallet"),
            summary="Potential wallet secret detected; evidence is redacted.",
        ))

    if encoded_secret:
        findings.append(_finding(
            rule_id="CRYPTO-SECRET-002",
            title="Possible encoded private wallet key",
            severity=Severity.critical,
            confidence=Confidence.medium,
            description="A private-key-named variable contains a hex or base58 value with a wallet-key-like length.",
            impact="A committed signing key may allow unauthorized asset transfers.",
            guidance="Validate without copying the value. If genuine, rotate the wallet immediately and purge repository history.",
            path=path, text=text, offset=encoded_secret.start(), tags=("crypto", "secret", "encoded"),
            summary="Possible encoded wallet secret detected; evidence is redacted.",
        ))

    if crypto_env:
        findings.append(_finding(
            rule_id="CRYPTO-ENV-001",
            title="Wallet secret environment access",
            severity=Severity.medium,
            confidence=Confidence.high,
            description="The source reads an environment variable whose name indicates wallet or signing material.",
            impact="A reachable data flow may expose an injected wallet key, seed, or recovery phrase.",
            guidance="Trace the value to every network, process, log, and persistence sink. Prefer isolated signing interfaces.",
            path=path, text=text, offset=crypto_env.start(), tags=("crypto", "environment", "wallet"),
            summary="A wallet-secret-named environment variable is accessed.",
        ))

    for wallet in wallet_matches:
        findings.append(_finding(
            rule_id="CRYPTO-WALLET-001",
            title=f"{wallet.family} storage path access",
            severity=Severity.high,
            confidence=Confidence.high,
            description="The source references a path associated with local wallet or signing material.",
            impact="Reachable file access may expose wallet databases, keystores, or signing identities.",
            guidance="Trace the concrete filesystem operation and determine whether the data can reach a process or network sink.",
            path=path, text=text, offset=wallet.match.start(), tags=("crypto", "filesystem", "wallet"),
            summary=f"A {wallet.family} storage location is referenced.",
        ))

    assignments = _assignments(text)
    initial_tainted = {
        name
        for name, expression, _offset in assignments
        if _contains_sensitive_source(expression)
    }
    tainted = _propagate_variables(assignments, initial_tainted)
    sensitive_present = bool(private_key or mnemonic or encoded_secret or wallet_matches or crypto_env)
    network_flow = _tainted_call(text, _NETWORK_CALL, tainted)
    process_flow = _tainted_call(text, _PROCESS_CALL, tainted)

    if network_flow:
        offset, _call, used = network_flow
        variable_summary = ", ".join(used[:8]) if used else "a direct sensitive expression"
        findings.append(_finding(
            rule_id="CRYPTO-TX-001",
            title="Wallet data reaches an outbound network sink",
            severity=Severity.critical,
            confidence=Confidence.high,
            description="Bounded intra-file tracking connects wallet-sensitive input to a network call.",
            impact="Private wallet material may be transmitted outside the host.",
            guidance="Inspect the complete request, destination ownership, trigger, and consent path. Remove transmission of private material.",
            path=path, text=text, offset=offset, tags=("crypto", "network", "data-flow"),
            summary=f"Tracked sensitive value reaches a network sink through {variable_summary}.",
        ))
    elif sensitive_present and (network := _NETWORK_CALL.search(text)):
        findings.append(_finding(
            rule_id="CRYPTO-PROX-001",
            title="Wallet-sensitive and network capabilities are colocated",
            severity=Severity.high,
            confidence=Confidence.medium,
            description="Wallet-sensitive material and a network call occur in the same file, but bounded tracking did not connect them.",
            impact="A data flow may exist through unsupported syntax, callbacks, objects, or cross-file state.",
            guidance="Review the source manually before treating this as exfiltration; trace object properties and cross-function calls.",
            path=path, text=text, offset=network.start(), tags=("crypto", "network", "proximity"),
            summary="Sensitive and network capabilities are colocated without a confirmed bounded flow.",
        ))

    if process_flow:
        offset, _call, used = process_flow
        variable_summary = ", ".join(used[:8]) if used else "a direct sensitive expression"
        findings.append(_finding(
            rule_id="CRYPTO-PROC-001",
            title="Wallet data reaches a process execution sink",
            severity=Severity.critical,
            confidence=Confidence.high,
            description="Bounded intra-file tracking connects wallet-sensitive input to process execution arguments.",
            impact="Private material may leak through command arguments, child-process input, logs, or invoked tooling.",
            guidance="Remove wallet material from process arguments and inspect the invoked executable and every transformation.",
            path=path, text=text, offset=offset, tags=("crypto", "process", "data-flow"),
            summary=f"Tracked sensitive value reaches a process sink through {variable_summary}.",
        ))

    clipboard_read = _CLIPBOARD_READ.search(text)
    address_variables = _address_variables(assignments)
    if clipboard_read:
        for write in _CLIPBOARD_WRITE.finditer(text):
            call = _balanced_call(text, write.start())
            used_addresses = sorted(
                name for name in address_variables if _identifier_in(call, name)
            )
            if _CRYPTO_ADDRESS.search(call) or used_addresses:
                destination = ", ".join(used_addresses[:8]) if used_addresses else "a hard-coded address"
                findings.append(_finding(
                    rule_id="CRYPTO-CLIP-001",
                    title="Potential clipboard wallet-address replacement",
                    severity=Severity.critical,
                    confidence=Confidence.high,
                    description="The source reads the clipboard and writes a cryptocurrency address or an address-bearing variable.",
                    impact="A copied payment address could be replaced before the user pastes it.",
                    guidance="Trace the clipboard trigger and destination. Remove silent replacement and require explicit user confirmation.",
                    path=path, text=text, offset=write.start(), tags=("crypto", "clipboard", "address-replacement"),
                    summary=f"Clipboard content can be replaced with {destination}.",
                ))
                break

    return findings
