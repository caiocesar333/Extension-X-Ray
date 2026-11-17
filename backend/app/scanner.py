from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .models import (
    Confidence,
    FileEntry,
    Finding,
    FindingEvidence,
    ModuleEdge,
    ModuleGraph,
    ModuleNode,
    Severity,
    SourceLocation,
)

_SOURCE_KINDS = {"javascript", "typescript"}
_MAX_SCANNED_FILE_BYTES = 2 * 1024 * 1024
_MAX_FINDINGS = 500
_IMPORT_PATTERN = re.compile(
    r"(?:import\s+(?:[^'\"]*?\s+from\s+)?|export\s+[^'\"]*?\s+from\s+|require\s*\()"
    r"['\"]([^'\"]+)['\"]"
)


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    modules: ModuleGraph
    limitations: list[str]


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    pattern: re.Pattern[str]
    description: str
    impact: str
    guidance: str
    tags: tuple[str, ...]


_RULES = (
    _Rule(
        "EXR-PROC-001",
        "Process execution API",
        Severity.high,
        Confidence.high,
        re.compile(
            r"(?:child_process\s*\.\s*(?:exec|execFile|spawn|fork|execSync|execFileSync|spawnSync)|"
            r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.\s*(?:exec|execFile|spawn|fork|execSync|execFileSync|spawnSync))\s*\("
        ),
        "The extension contains a call associated with starting an operating-system process.",
        "If reachable with attacker-controlled input, this can run commands with the editor user's privileges.",
        "Trace the arguments and call path. Prefer constrained APIs, fixed argument lists, and explicit user consent.",
        ("process", "execution"),
    ),
    _Rule(
        "EXR-DYN-001",
        "Dynamic JavaScript execution",
        Severity.high,
        Confidence.high,
        re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]"),
        "The extension dynamically compiles or evaluates JavaScript.",
        "Dynamic code can conceal behavior and turn untrusted strings into executable code.",
        "Confirm the input is entirely trusted and replace dynamic evaluation with explicit parsing or dispatch.",
        ("dynamic-code",),
    ),
    _Rule(
        "EXR-ENV-001",
        "Environment variable access",
        Severity.medium,
        Confidence.high,
        re.compile(r"\bprocess\s*\.\s*env\b|\bDeno\s*\.\s*env\b"),
        "The extension reads process environment variables.",
        "Environment variables can contain tokens, credentials, proxy settings, and private paths.",
        "Verify which variables are accessed, why they are required, and whether their values can leave the host.",
        ("environment", "credentials"),
    ),
    _Rule(
        "EXR-NET-001",
        "Outbound network capability",
        Severity.medium,
        Confidence.medium,
        re.compile(
            r"\bfetch\s*\(|\bnew\s+WebSocket\s*\(|\b(?:https?|axios)\s*\.\s*(?:get|post|put|request)\s*\(|"
            r"require\s*\(\s*['\"](?:node:)?https?['\"]\s*\)"
        ),
        "The extension contains an API associated with outbound network communication.",
        "Network access can transmit project data or retrieve remote content; this finding alone does not prove either.",
        "Review destinations, payload construction, TLS handling, telemetry disclosure, and user controls.",
        ("network",),
    ),
    _Rule(
        "EXR-OBF-001",
        "Obfuscation indicator",
        Severity.medium,
        Confidence.medium,
        re.compile(
            r"(?:\\x[0-9a-fA-F]{2}){10,}|\b(?:atob|String\s*\.\s*fromCharCode)\s*\(|"
            r"['\"][A-Za-z0-9+/]{240,}={0,2}['\"]"
        ),
        "The source contains an encoding or construction pattern commonly seen in obfuscated bundles.",
        "Obfuscation makes review harder and can hide security-relevant behavior, but may also be generated build output.",
        "Locate the source map or original source and determine what the encoded value produces without executing it.",
        ("obfuscation",),
    ),
)

_FS_ACCESS = re.compile(
    r"(?:require\s*\(\s*['\"](?:node:)?fs(?:/promises)?['\"]|\bfs\s*\.\s*(?:readFile|writeFile|open|createReadStream|createWriteStream)|"
    r"\b(?:readFile|writeFile|createReadStream|createWriteStream)\s*\()"
)
_SENSITIVE_PATH = re.compile(
    r"(?:[/\\]\.ssh(?:[/\\]|['\"])|[/\\]\.aws(?:[/\\]|['\"])|[/\\]\.config(?:[/\\]|['\"])|"
    r"/etc/(?:passwd|shadow)|\bid_rsa\b|\bcredentials\b|\bkeychain\b|\bAppData[/\\]Roaming\b)",
    re.IGNORECASE,
)
_PROCESS_METHODS = {"exec", "execFile", "spawn", "fork", "execSync", "execFileSync", "spawnSync"}
_PROCESS_MODULE_BINDING = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
    r"|import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?child_process['\"]"
)
_PROCESS_NAMED_BINDING = re.compile(
    r"(?:const|let|var)\s*\{([^}]{1,500})\}\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
    r"|import\s*\{([^}]{1,500})\}\s*from\s*['\"](?:node:)?child_process['\"]"
)


def _line_details(text: str, offset: int) -> tuple[int, int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    snippet = text[start:end].strip().replace("\x00", "")[:320]
    return line, offset - start + 1, snippet


def _process_execution_matches(text: str, direct_pattern: re.Pattern[str]) -> list[re.Match[str]]:
    matches = list(direct_pattern.finditer(text))
    module_aliases = {
        alias
        for binding in _PROCESS_MODULE_BINDING.finditer(text)
        for alias in binding.groups()
        if alias
    }
    for alias in module_aliases:
        pattern = re.compile(
            rf"\b{re.escape(alias)}\s*\.\s*(?:{'|'.join(sorted(_PROCESS_METHODS, key=len, reverse=True))})\s*\("
        )
        matches.extend(pattern.finditer(text))

    function_aliases: set[str] = set()
    for binding in _PROCESS_NAMED_BINDING.finditer(text):
        body = next((group for group in binding.groups() if group is not None), "")
        for raw_part in body.split(","):
            part = raw_part.strip()
            candidate = re.fullmatch(
                r"([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?",
                part,
            )
            if candidate and candidate.group(1) in _PROCESS_METHODS:
                function_aliases.add(candidate.group(2) or candidate.group(1))
    for alias in function_aliases:
        matches.extend(re.finditer(rf"(?<![\w$.]){re.escape(alias)}\s*\(", text))
    return sorted({match.start(): match for match in matches}.values(), key=lambda match: match.start())


def _finding(
    rule: _Rule,
    path: str,
    text: str,
    offset: int,
    *,
    summary: str | None = None,
    source: str = "native",
) -> Finding:
    line, column, snippet = _line_details(text, offset)
    digest = hashlib.sha256(f"{rule.rule_id}:{path}:{line}:{snippet}".encode()).hexdigest()[:16]
    return Finding(
        id=f"finding-{digest}",
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        evidence=FindingEvidence(summary=summary or f"Matched static pattern for {rule.rule_id}", snippet=snippet),
        location=SourceLocation(file=path, line=line, column=column),
        potential_impact=rule.impact,
        guidance=rule.guidance,
        tags=list(rule.tags),
        source=source,
    )


def _combination_finding(
    path: str,
    text: str,
    offset: int,
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    impact: str,
    guidance: str,
    tags: tuple[str, ...],
) -> Finding:
    rule = _Rule(
        rule_id,
        title,
        severity,
        Confidence.high,
        re.compile(""),
        description,
        impact,
        guidance,
        tags,
    )
    return _finding(rule, path, text, offset, summary="Multiple security-relevant capabilities occur in the same file")


def _node_id(kind: str, value: str) -> str:
    return f"mod-{hashlib.sha256(f'{kind}:{value}'.encode()).hexdigest()[:14]}"


def _resolve_relative(source_path: str, specifier: str, known: set[str]) -> str | None:
    base = PurePosixPath(source_path).parent.joinpath(specifier)
    parts: list[str] = []
    for part in base.parts:
        if part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    normalized = "/".join(parts)
    candidates = [normalized, *(normalized + suffix for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx"))]
    candidates.extend(f"{normalized}/index{suffix}" for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx"))
    return next((candidate for candidate in candidates if candidate in known), None)


def scan_sources(root: Path, files: list[FileEntry]) -> ScanResult:
    source_entries = [entry for entry in files if entry.kind in _SOURCE_KINDS]
    known_paths = {entry.path for entry in source_entries}
    findings: list[Finding] = []
    limitations: list[str] = []
    texts: dict[str, str] = {}

    for entry in source_entries:
        if entry.size > _MAX_SCANNED_FILE_BYTES:
            limitations.append(f"Native scan skipped {entry.path}: file exceeds 2 MiB scan limit.")
            continue
        try:
            data = root.joinpath(*entry.path.split("/")).read_bytes()
            texts[entry.path] = data.decode("utf-8", errors="replace")
        except OSError:
            limitations.append(f"Native scan could not read {entry.path}.")

    for path, text in texts.items():
        matches_by_rule: dict[str, re.Match[str]] = {}
        for rule in _RULES:
            matches = (
                _process_execution_matches(text, rule.pattern)
                if rule.rule_id == "EXR-PROC-001"
                else rule.pattern.finditer(text)
            )
            for match in matches:
                findings.append(_finding(rule, path, text, match.start()))
                matches_by_rule.setdefault(rule.rule_id, match)
                if len(findings) >= _MAX_FINDINGS:
                    break
            if len(findings) >= _MAX_FINDINGS:
                break

        fs_match = _FS_ACCESS.search(text)
        sensitive_match = _SENSITIVE_PATH.search(text)
        if fs_match and sensitive_match:
            fs_rule = _Rule(
                "EXR-FS-001",
                "Sensitive filesystem path access",
                Severity.high,
                Confidence.medium,
                _SENSITIVE_PATH,
                "Filesystem APIs and a sensitive user or system path occur in the same source file.",
                "The extension may be able to read credentials, keys, or private configuration.",
                "Trace the concrete path and operation, minimize scope, and require an explicit user action.",
                ("filesystem", "credentials"),
            )
            findings.append(_finding(fs_rule, path, text, sensitive_match.start()))

        network = matches_by_rule.get("EXR-NET-001")
        environment = matches_by_rule.get("EXR-ENV-001")
        process = matches_by_rule.get("EXR-PROC-001")
        dynamic = matches_by_rule.get("EXR-DYN-001")
        if network and (environment or (fs_match and sensitive_match)):
            findings.append(
                _combination_finding(
                    path,
                    text,
                    network.start(),
                    rule_id="EXR-TX-001",
                    title="Potential sensitive data transmission chain",
                    severity=Severity.critical,
                    description="Sensitive data access and network capability are present in the same file.",
                    impact="A reachable data flow could transmit environment values or sensitive file contents.",
                    guidance="Manually trace values from each source to every outbound request. Confirm consent and destination ownership.",
                    tags=("network", "data-flow", "dangerous-combination"),
                )
            )
        if network and process:
            findings.append(
                _combination_finding(
                    path,
                    text,
                    process.start(),
                    rule_id="EXR-DLX-001",
                    title="Download-and-execute capability combination",
                    severity=Severity.critical,
                    description="Network and operating-system process capabilities are present in the same file.",
                    impact="If connected by a data flow, remote content could influence local command execution.",
                    guidance="Trace downloaded values and process arguments. Require integrity verification and avoid executing remote content.",
                    tags=("network", "process", "dangerous-combination"),
                )
            )
        if network and dynamic:
            findings.append(
                _combination_finding(
                    path,
                    text,
                    dynamic.start(),
                    rule_id="EXR-CAP-001",
                    title="Network and dynamic execution combination",
                    severity=Severity.high,
                    description="Network access and dynamic JavaScript execution occur in the same source file.",
                    impact="Remote or attacker-influenced strings could become executable JavaScript if the flows connect.",
                    guidance="Verify the data flow and replace dynamic evaluation with a non-executable data format.",
                    tags=("network", "dynamic-code", "dangerous-combination"),
                )
            )
        if len(findings) >= _MAX_FINDINGS:
            limitations.append(f"Native findings were capped at {_MAX_FINDINGS} results.")
            findings = findings[:_MAX_FINDINGS]
            break

    nodes: dict[str, ModuleNode] = {}
    edges: list[ModuleEdge] = []
    for path, text in texts.items():
        source_id = _node_id("file", path)
        nodes[source_id] = ModuleNode(
            id=source_id,
            label=PurePosixPath(path).name,
            path=path,
            kind="source",
        )
        for match in _IMPORT_PATTERN.finditer(text):
            specifier = match.group(1)
            resolved = _resolve_relative(path, specifier, known_paths) if specifier.startswith(".") else None
            target_value = resolved or specifier
            target_kind = "source" if resolved else ("builtin" if specifier.startswith("node:") else "external")
            target_id = _node_id("file" if resolved else target_kind, target_value)
            nodes.setdefault(
                target_id,
                ModuleNode(
                    id=target_id,
                    label=PurePosixPath(target_value).name if resolved else target_value,
                    path=resolved,
                    kind=target_kind,
                ),
            )
            edges.append(ModuleEdge(source=source_id, target=target_id, specifier=specifier[:500]))

    severity_order = {
        Severity.critical: 0,
        Severity.high: 1,
        Severity.medium: 2,
        Severity.low: 3,
        Severity.info: 4,
    }
    findings.sort(
        key=lambda item: (
            severity_order[item.severity],
            item.location.file if item.location else "",
            item.location.line if item.location and item.location.line else 0,
            item.rule_id,
        )
    )
    return ScanResult(
        findings=findings,
        modules=ModuleGraph(nodes=list(nodes.values()), edges=edges, source="native"),
        limitations=limitations,
    )

