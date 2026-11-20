from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .models import Confidence, FileEntry, Finding, FindingEvidence, Severity, SourceLocation

_MAX_TEXT_BYTES = 2 * 1024 * 1024
_MAX_FINDINGS = 500
_TEXT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".json", ".jsonc", ".yml", ".yaml", ".toml", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".dockerfile", ".env", ".txt",
}
_NETWORK = re.compile(r"\bfetch\s*\(|\b(?:https?|axios)\s*\.\s*(?:get|post|request)\s*\(|\b(?:curl|wget|Invoke-WebRequest)\b", re.IGNORECASE)
_WALLET_PATH = re.compile(
    r"(?:wallet\.dat|[/\\](?:\.bitcoin|\.ethereum|\.config[/\\]solana)(?:[/\\]|['\"])|"
    r"[/\\](?:keystore|wallets?)(?:[/\\]|['\"])|Local Extension Settings)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_MNEMONIC_ASSIGNMENT = re.compile(
    r"\b(?:seedPhrase|seed_phrase|mnemonic|recoveryPhrase)\b\s*[:=]\s*['\"]([^'\"\r\n]{40,500})['\"]",
    re.IGNORECASE,
)
_CLIPBOARD_READ = re.compile(r"(?:clipboard\s*\.\s*readText|readClipboard|Get-Clipboard)\s*\(?", re.IGNORECASE)
_CLIPBOARD_WRITE = re.compile(r"(?:clipboard\s*\.\s*writeText|writeClipboard|Set-Clipboard)\s*\(?", re.IGNORECASE)
_CRYPTO_ADDRESS = re.compile(r"(?:\b0x[a-fA-F0-9]{40}\b|\bbc1[a-zA-HJ-NP-Z0-9]{20,90}\b)")
_DOWNLOAD_EXEC = re.compile(
    r"(?:curl|wget|Invoke-WebRequest)[^\r\n|;]{0,500}(?:\||;|&&)\s*(?:sh|bash|zsh|powershell|pwsh|cmd)\b|"
    r"powershell(?:\.exe)?\s+(?:-[Ee]ncodedCommand|-enc)\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class RepositoryScanResult:
    findings: list[Finding]
    limitations: list[str]


def _line_details(text: str, offset: int) -> tuple[int, int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return line, offset - start + 1, text[start:end].strip().replace("\x00", "")[:320]


def _redact(snippet: str) -> str:
    if _PRIVATE_KEY.search(snippet):
        return "[REDACTED: private key material]"
    if _MNEMONIC_ASSIGNMENT.search(snippet):
        return re.sub(
            r"(['\"])[^'\"]+\1",
            "\"[REDACTED: possible recovery phrase]\"",
            snippet,
            count=1,
        )
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
    safe_snippet = _redact(snippet)
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
        source="repository-native",
    )


def _append(findings: list[Finding], finding: Finding) -> None:
    if len(findings) < _MAX_FINDINGS and all(item.id != finding.id for item in findings):
        findings.append(finding)


def _scan_package_json(path: str, text: str, findings: list[Finding]) -> None:
    try:
        package = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(package, dict) or not isinstance(package.get("scripts"), dict):
        return
    for name, command in list(package["scripts"].items())[:500]:
        if not isinstance(name, str) or not isinstance(command, str):
            continue
        offset = text.find(json.dumps(command))
        offset = offset if offset >= 0 else max(text.find(command), 0)
        if name.lower() in {"preinstall", "install", "postinstall", "prepare"}:
            networked = bool(_NETWORK.search(command) or _DOWNLOAD_EXEC.search(command))
            _append(findings, _finding(
                rule_id="REP-NPM-002" if networked else "REP-NPM-001",
                title="Networked package lifecycle script" if networked else "Package lifecycle script",
                severity=Severity.critical if networked else Severity.medium,
                confidence=Confidence.high,
                description="A package lifecycle hook can run automatically during dependency installation.",
                impact="The command can execute with the developer's privileges before the project is reviewed.",
                guidance="Inspect the referenced script as data. Do not install dependencies until the hook and its inputs are trusted.",
                path=path,
                text=text,
                offset=offset,
                tags=("supply-chain", "package-script", "execution"),
                summary=f"Lifecycle script {name!r} is declared in package.json.",
            ))


def _scan_workflow(path: str, text: str, findings: list[Finding]) -> None:
    pull_target = re.search(
        r"^\s*(?:pull_request_target\s*:|['\"]?on['\"]?\s*:\s*(?:\[[^\]\r\n]*\b)?pull_request_target\b)",
        text,
        re.MULTILINE,
    )
    untrusted_ref = re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)", text)
    run_step = re.search(r"^\s*(?:-\s*)?run\s*:", text, re.MULTILINE)
    if pull_target and untrusted_ref and run_step:
        _append(findings, _finding(
            rule_id="REP-CI-001",
            title="Privileged workflow executes pull-request code",
            severity=Severity.critical,
            confidence=Confidence.high,
            description="A pull_request_target workflow checks out attacker-controlled pull-request code and later runs commands.",
            impact="Fork-controlled code may execute with repository secrets or a privileged GITHUB_TOKEN.",
            guidance="Use pull_request with restricted permissions, or separate untrusted execution from any job that has secrets or write access.",
            path=path,
            text=text,
            offset=pull_target.start(),
            tags=("github-actions", "pwn-request", "secrets"),
            summary="pull_request_target, pull-request head checkout, and a run step occur in the same workflow.",
        ))
    injection = re.search(
        r"^\s*(?:-\s*)?run\s*:[^\r\n]*(?:\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit)[^}]*\}\})",
        text,
        re.MULTILINE,
    )
    if injection:
        _append(findings, _finding(
            rule_id="REP-CI-002",
            title="Potential GitHub Actions script injection",
            severity=Severity.high,
            confidence=Confidence.medium,
            description="Untrusted event text is interpolated directly into a workflow run command.",
            impact="Crafted issue, commit, branch, or pull-request text may be interpreted as shell syntax.",
            guidance="Pass the value through an environment variable and quote it in the selected shell.",
            path=path,
            text=text,
            offset=injection.start(),
            tags=("github-actions", "injection"),
            summary="A run step directly references attacker-influenced github.event data.",
        ))
    for action in re.finditer(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", text, re.MULTILINE):
        reference = action.group(1).strip("'\"")
        if reference.startswith(("./", "docker://")) or "@" not in reference:
            continue
        revision = reference.rsplit("@", 1)[1]
        if not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
            _append(findings, _finding(
                rule_id="REP-CI-003",
                title="GitHub Action is not pinned to an immutable commit",
                severity=Severity.medium,
                confidence=Confidence.high,
                description="The workflow references an action by a mutable tag or branch instead of a full commit SHA.",
                impact="A compromised or retargeted upstream reference can change code executed by the workflow.",
                guidance="Pin the action to a verified full-length commit SHA and document the human-readable release beside it.",
                path=path,
                text=text,
                offset=action.start(),
                tags=("github-actions", "supply-chain"),
                summary=f"Mutable action reference: {reference[:200]}",
            ))


def _scan_repository_config(path: str, text: str, findings: list[Finding]) -> None:
    parts = PurePosixPath(path).parts
    name = PurePosixPath(path).name
    if ".vscode" in parts and name == "tasks.json":
        match = re.search(r"['\"](?:command|dependsOn)['\"]\s*:", text)
        if match:
            _append(findings, _finding(
                rule_id="REP-IDE-001",
                title="Workspace task can execute a command",
                severity=Severity.medium,
                confidence=Confidence.high,
                description="The repository defines a VS Code task that can launch commands from the workspace.",
                impact="Running or automatically invoking the task executes repository-controlled commands.",
                guidance="Keep the workspace in Restricted Mode and inspect the complete task and dependencies before running it.",
                path=path, text=text, offset=match.start(), tags=("vscode", "workspace", "execution"),
                summary="A command-bearing VS Code task is committed in the repository.",
            ))
    if ".devcontainer" in parts and name.endswith(".json"):
        match = re.search(r"['\"](?:initializeCommand|onCreateCommand|postCreateCommand|postStartCommand)['\"]\s*:", text)
        if match:
            _append(findings, _finding(
                rule_id="REP-DEV-001",
                title="Dev container lifecycle command",
                severity=Severity.high,
                confidence=Confidence.high,
                description="The devcontainer configuration defines a command that runs during container setup or startup.",
                impact="Opening the project in a dev container can execute repository-controlled code.",
                guidance="Inspect the command and referenced files before creating or reopening the container.",
                path=path, text=text, offset=match.start(), tags=("devcontainer", "execution"),
                summary="A devcontainer lifecycle command is declared.",
            ))


def _scan_crypto(path: str, text: str, findings: list[Finding]) -> None:
    private_key = _PRIVATE_KEY.search(text)
    mnemonic = _MNEMONIC_ASSIGNMENT.search(text)
    wallet_path = _WALLET_PATH.search(text)
    network = _NETWORK.search(text)
    clipboard_read = _CLIPBOARD_READ.search(text)
    clipboard_write = _CLIPBOARD_WRITE.search(text)
    crypto_address = _CRYPTO_ADDRESS.search(text)
    sensitive = private_key or mnemonic or wallet_path
    if private_key or mnemonic:
        match = private_key or mnemonic
        assert match is not None
        _append(findings, _finding(
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
    if wallet_path:
        _append(findings, _finding(
            rule_id="CRYPTO-WALLET-001",
            title="Wallet storage path access",
            severity=Severity.high,
            confidence=Confidence.medium,
            description="The source references a path commonly associated with local wallet material.",
            impact="Reachable file access may expose wallet databases, keystores, or signing identities.",
            guidance="Trace the concrete filesystem operation and determine whether the path can leave the host.",
            path=path, text=text, offset=wallet_path.start(), tags=("crypto", "filesystem", "wallet"),
            summary="A wallet-related local path is referenced.",
        ))
    if sensitive and network:
        _append(findings, _finding(
            rule_id="CRYPTO-TX-001",
            title="Potential wallet data exfiltration chain",
            severity=Severity.critical,
            confidence=Confidence.high,
            description="Wallet-sensitive material and outbound network capability occur in the same source file.",
            impact="If the values flow together, wallet credentials or local wallet files could be transmitted.",
            guidance="Trace data from the sensitive source into every request body, URL, header, and process argument.",
            path=path, text=text, offset=network.start(), tags=("crypto", "network", "dangerous-combination"),
            summary="Wallet-sensitive access and a network sink are colocated.",
        ))
    if clipboard_read and clipboard_write and crypto_address:
        _append(findings, _finding(
            rule_id="CRYPTO-CLIP-001",
            title="Potential clipboard address replacement",
            severity=Severity.critical,
            confidence=Confidence.high,
            description="The source reads and writes the clipboard while containing a cryptocurrency address pattern.",
            impact="A copied payment address could be replaced before the user pastes it.",
            guidance="Trace the clipboard transformation and verify every replacement destination and trigger.",
            path=path, text=text, offset=clipboard_write.start(), tags=("crypto", "clipboard", "address-replacement"),
            summary="Clipboard read/write and a cryptocurrency address occur in the same file.",
        ))


def scan_repository(root: Path, files: list[FileEntry]) -> RepositoryScanResult:
    findings: list[Finding] = []
    limitations: list[str] = []
    for entry in files:
        path = entry.path
        pure = PurePosixPath(path)
        if "node_modules" in pure.parts or ".git" in pure.parts:
            continue
        is_known_text = entry.kind in {"javascript", "typescript", "json", "text", "script"} or pure.suffix.lower() in _TEXT_SUFFIXES or pure.name in {"Dockerfile", "Makefile", "yarn.lock"}
        if not is_known_text:
            continue
        if entry.size > _MAX_TEXT_BYTES:
            limitations.append(f"Repository rules skipped {path}: file exceeds 2 MiB text limit.")
            continue
        try:
            text = root.joinpath(*path.split("/")).read_bytes().decode("utf-8", errors="replace")
        except OSError:
            limitations.append(f"Repository rules could not read {path}.")
            continue
        if pure.name == "package.json":
            _scan_package_json(path, text, findings)
        if ".github" in pure.parts and "workflows" in pure.parts and pure.suffix.lower() in {".yml", ".yaml"}:
            _scan_workflow(path, text, findings)
        _scan_repository_config(path, text, findings)
        _scan_crypto(path, text, findings)
        download = _DOWNLOAD_EXEC.search(text)
        if download:
            _append(findings, _finding(
                rule_id="REP-DLX-001",
                title="Download-and-execute command",
                severity=Severity.critical,
                confidence=Confidence.high,
                description="A shell command downloads remote content and forwards it to a command interpreter.",
                impact="Remote content can execute immediately with the current user's or CI runner's privileges.",
                guidance="Remove the pipeline. Download a versioned artifact separately and verify its digest and provenance before use.",
                path=path, text=text, offset=download.start(), tags=("download", "execution", "supply-chain"),
                summary="A download command is chained directly into an interpreter.",
            ))
        if len(findings) >= _MAX_FINDINGS:
            limitations.append(f"Repository findings were capped at {_MAX_FINDINGS} results.")
            break
    severity_order = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3, Severity.info: 4}
    findings.sort(key=lambda finding: (severity_order[finding.severity], finding.location.file if finding.location else "", finding.location.line if finding.location and finding.location.line else 0, finding.rule_id))
    return RepositoryScanResult(findings=findings, limitations=limitations)

