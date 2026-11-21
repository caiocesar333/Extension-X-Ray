from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .crypto_guard import redact_sensitive_evidence, scan_crypto_file
from .models import Confidence, FileEntry, Finding, FindingEvidence, Severity, SourceLocation

_MAX_TEXT_BYTES = 2 * 1024 * 1024
_MAX_FINDINGS = 500
_CI_CONTROL_FILES = {".extension-xray-baseline.json"}
_TEXT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".json", ".jsonc", ".yml", ".yaml", ".toml", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".py", ".dockerfile", ".env", ".txt",
}
_NETWORK = re.compile(r"\bfetch\s*\(|\b(?:https?|axios)\s*\.\s*(?:get|post|request)\s*\(|\b(?:curl|wget|Invoke-WebRequest)\b", re.IGNORECASE)
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


def _workflow_job_blocks(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line)

    jobs_index: int | None = None
    jobs_indent = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)jobs\s*:\s*(?:#.*)?$", line.rstrip("\r\n"))
        if match:
            jobs_index = index
            jobs_indent = len(match.group(1))
            break
    if jobs_index is None:
        return []

    starts: list[tuple[int, int]] = []
    job_indent: int | None = None
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= jobs_indent:
            break
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\s*:\s*(?:#.*)?", stripped):
            continue
        if job_indent is None:
            job_indent = indent
        if indent == job_indent:
            starts.append((index, offsets[index]))

    blocks: list[tuple[int, str]] = []
    for position, (line_index, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(text)
        if position + 1 == len(starts):
            for index in range(line_index + 1, len(lines)):
                stripped = lines[index].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                indent = len(lines[index]) - len(lines[index].lstrip(" "))
                if indent <= jobs_indent:
                    end = offsets[index]
                    break
        blocks.append((start, text[start:end]))
    return blocks


def _run_sections(text: str, base_offset: int = 0) -> list[tuple[int, str]]:
    lines = text.splitlines(keepends=True)
    sections: list[tuple[int, str]] = []
    cursor = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$", line.rstrip("\r\n"))
        line_offset = cursor
        cursor += len(line)
        if not match:
            continue
        content = match.group(2).strip()
        if not content or re.fullmatch(r"[>|][0-9+-]*", content):
            block_indent = len(match.group(1))
            following: list[str] = []
            for candidate in lines[index + 1:]:
                candidate_text = candidate.rstrip("\r\n")
                if not candidate_text.strip():
                    following.append(candidate_text)
                    continue
                indent = len(candidate) - len(candidate.lstrip(" "))
                if indent <= block_indent:
                    break
                following.append(candidate_text)
            content = "\n".join(following)
        sections.append((base_offset + line_offset + match.start(), content))
    return sections


def _scan_workflow(path: str, text: str, findings: list[Finding]) -> None:
    pull_target = re.search(
        r"^\s*(?:pull_request_target\s*:|['\"]?on['\"]?\s*:\s*(?:\[[^\]\r\n]*\b)?pull_request_target\b)",
        text,
        re.MULTILINE,
    )
    dangerous_job = next(
        (
            (offset, block)
            for offset, block in _workflow_job_blocks(text)
            if re.search(r"\buses\s*:\s*['\"]?actions/checkout@", block, re.IGNORECASE)
            and re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)", block)
            and _run_sections(block, offset)
        ),
        None,
    )
    if pull_target and dangerous_job:
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
            summary="pull_request_target, pull-request head checkout, and a run step occur in the same job.",
        ))
    event_expression = re.compile(
        r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|head_commit|discussion|review|workflow_run)|head_ref)[^}]*\}\}",
    )
    injection = next(
        (
            (offset, section)
            for offset, section in _run_sections(text)
            if event_expression.search(section)
        ),
        None,
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
            offset=injection[0],
            tags=("github-actions", "injection"),
            summary="A run step directly references attacker-influenced github.event data.",
        ))
    mutable_actions: list[re.Match[str]] = []
    for action in re.finditer(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", text, re.MULTILINE):
        reference = action.group(1).strip("'\"")
        if reference.startswith(("./", "docker://")) or "@" not in reference:
            continue
        revision = reference.rsplit("@", 1)[1]
        if not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
            mutable_actions.append(action)
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
    write_all = re.search(r"^\s*permissions\s*:\s*write-all\b", text, re.MULTILINE | re.IGNORECASE)
    if write_all:
        _append(findings, _finding(
            rule_id="SCM-CI-001",
            title="GitHub Actions grants write-all permissions",
            severity=Severity.high,
            confidence=Confidence.high,
            description="The workflow grants every available GITHUB_TOKEN permission write access.",
            impact="Compromised workflow code or dependencies may modify repository contents, releases, packages, or actions.",
            guidance="Set read-all by default and grant only the minimum write permission to the specific job that needs it.",
            path=path, text=text, offset=write_all.start(), tags=("supply-chain", "github-actions", "permissions"),
            summary="The workflow declares permissions: write-all.",
        ))
    oidc_write = re.search(r"^\s*id-token\s*:\s*write\b", text, re.MULTILINE | re.IGNORECASE)
    if oidc_write and mutable_actions:
        action = mutable_actions[0]
        _append(findings, _finding(
            rule_id="SCM-CI-002",
            title="OIDC credential permission is combined with a mutable Action",
            severity=Severity.high,
            confidence=Confidence.high,
            description="The workflow can request an OIDC token while executing an Action that is not pinned to a full commit SHA.",
            impact="A compromised or retargeted Action may obtain federated cloud credentials under the workflow trust policy.",
            guidance="Pin every Action in the credential-bearing job to a verified commit and restrict the cloud trust policy and job permissions.",
            path=path, text=text, offset=action.start(), tags=("supply-chain", "github-actions", "oidc"),
            summary="id-token: write is present with a mutable Action reference.",
        ))
    secret_expression = re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}")
    secret_run = next(
        ((offset, section) for offset, section in _run_sections(text) if secret_expression.search(section)),
        None,
    )
    if secret_run:
        _append(findings, _finding(
            rule_id="SCM-CI-003",
            title="Secret is interpolated directly into a workflow script",
            severity=Severity.high,
            confidence=Confidence.medium,
            description="A secrets context expression is expanded directly inside a run script instead of crossing an explicit environment boundary.",
            impact="Shell quoting, command expansion, or accidental logging may expose or misuse the secret.",
            guidance="Pass the secret through a narrowly scoped environment variable, quote it for the selected shell, and avoid printing command traces.",
            path=path, text=text, offset=secret_run[0], tags=("supply-chain", "github-actions", "secrets"),
            summary="A run step directly interpolates a secrets.* expression.",
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


def scan_repository(root: Path, files: list[FileEntry]) -> RepositoryScanResult:
    findings: list[Finding] = []
    limitations: list[str] = []
    for entry in files:
        path = entry.path
        pure = PurePosixPath(path)
        if "node_modules" in pure.parts or ".git" in pure.parts:
            continue
        if pure.name in _CI_CONTROL_FILES:
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
        for crypto_finding in scan_crypto_file(path, text):
            _append(findings, crypto_finding)
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

