from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlparse

from .config import ArchiveLimits, SupplyChainSettings
from .crypto_guard import redact_sensitive_evidence
from .models import (
    AdvisoryDatabaseStatus,
    AdvisoryMatch,
    Confidence,
    CycloneDxBom,
    CycloneDxComponent,
    CycloneDxHash,
    CycloneDxProperty,
    FileEntry,
    Finding,
    FindingEvidence,
    LockfileIntegritySummary,
    Severity,
    SourceLocation,
    SupplyChainSummary,
)

_MAX_FINDINGS = 500
_POPULAR_NPM_PACKAGES = {
    "axios", "chalk", "commander", "dotenv", "eslint", "express", "lodash",
    "moment", "next", "prettier", "react", "request", "typescript", "uuid",
    "vite", "webpack", "zod",
}
_NON_REGISTRY_SPEC = re.compile(
    r"^(?:git@[^:\s]+:|(?:git(?:\+[^:]+)?|https?|github|gitlab|bitbucket|file|link|workspace):)",
    re.IGNORECASE,
)
_EXACT_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_SUPPORTED_INTEGRITY = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_EXPECTED_HASH_BYTES = {"sha256": 32, "sha384": 48, "sha512": 64}
_ALLOWED_REGISTRY_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}


@dataclass(frozen=True, order=True, slots=True)
class _SemVer:
    major: int
    minor: int
    patch: int
    stable: int
    prerelease: str


@dataclass(slots=True)
class SupplyChainResult:
    sbom: CycloneDxBom
    summary: SupplyChainSummary
    findings: list[Finding]
    limitations: list[str]


@dataclass(frozen=True, slots=True)
class _LockedPackage:
    path: str
    name: str
    version: str
    resolved: str | None
    integrity: str | None
    dev: bool
    optional: bool
    has_install_script: bool


def _semver(value: str) -> _SemVer | None:
    match = _EXACT_VERSION.fullmatch(value.strip())
    if not match:
        return None
    prerelease = match.group(4) or ""
    return _SemVer(
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        1 if not prerelease else 0,
        prerelease,
    )


def _line_details(text: str, offset: int) -> tuple[int, int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return line, offset - start + 1, text[start:end].strip().replace("\x00", "")[:320]


def _redact_supply_chain_evidence(value: str) -> str:
    safe_value = redact_sensitive_evidence(value)
    safe_value = re.sub(
        r"(https?://)[^/\s:@]+:[^@\s/]+@",
        r"\1[REDACTED]@",
        safe_value,
        flags=re.IGNORECASE,
    )
    return re.sub(
        r"(?i)((?:_authToken|token|password)[^:=\s]*\s*[:=]\s*['\"]?)[^'\"&\s,}]+",
        r"\1[REDACTED]",
        safe_value,
    )


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
    line, column, snippet = _line_details(text, max(offset, 0))
    safe_snippet = _redact_supply_chain_evidence(snippet)
    safe_summary = _redact_supply_chain_evidence(summary)
    digest = hashlib.sha256(f"{rule_id}:{path}:{line}:{safe_summary}".encode()).hexdigest()[:16]
    return Finding(
        id=f"finding-{digest}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=FindingEvidence(summary=safe_summary, snippet=safe_snippet),
        location=SourceLocation(file=path, line=line, column=column),
        potential_impact=impact,
        guidance=guidance,
        tags=list(tags),
        source="supply-chain",
    )


def _append(findings: list[Finding], finding: Finding) -> None:
    if len(findings) < _MAX_FINDINGS and all(item.id != finding.id for item in findings):
        findings.append(finding)


def _read_json(root: Path, entry: FileEntry | None, maximum: int) -> tuple[dict[str, Any], str]:
    if entry is None or entry.size > maximum:
        return {}, ""
    try:
        text = root.joinpath(*entry.path.split("/")).read_text(encoding="utf-8-sig")
        value = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, ""
    return (value if isinstance(value, dict) else {}), text


def _shallowest(files: list[FileEntry], name: str) -> FileEntry | None:
    candidates = [
        entry
        for entry in files
        if PurePosixPath(entry.path).name == name
        and "node_modules" not in PurePosixPath(entry.path).parts
    ]
    return min(
        candidates,
        key=lambda item: (len(PurePosixPath(item.path).parts), item.path.casefold()),
        default=None,
    )


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        key[:300]: item[:2_000]
        for key, item in list(value.items())[:10_000]
        if isinstance(key, str) and isinstance(item, str)
    }


def _direct_dependencies(package: dict[str, Any]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for field, scope in (
        ("dependencies", "required"),
        ("optionalDependencies", "optional"),
        ("devDependencies", "excluded"),
        ("peerDependencies", "required"),
    ):
        for name, specifier in _string_map(package.get(field)).items():
            result.setdefault(name, (specifier, scope))
    return result


def _lock_name(path: str) -> str | None:
    marker = "node_modules/"
    if marker not in path:
        return None
    name = path.rsplit(marker, 1)[1].strip("/")
    if not name or "/node_modules/" in name:
        return None
    return name


def _locked_packages(lock: dict[str, Any]) -> list[_LockedPackage]:
    packages = lock.get("packages")
    result: list[_LockedPackage] = []
    if isinstance(packages, dict):
        candidates = list(packages.items())[:10_000]
    else:
        candidates: list[tuple[str, Any]] = []
        pending: list[tuple[str, Any]] = [
            ("", lock.get("dependencies"))
        ]
        while pending and len(candidates) < 10_000:
            prefix, dependencies = pending.pop()
            if not isinstance(dependencies, dict):
                continue
            for name, raw in dependencies.items():
                if not isinstance(name, str) or not isinstance(raw, dict):
                    continue
                path = f"{prefix}node_modules/{name}"
                candidates.append((path, raw))
                pending.append((f"{path}/", raw.get("dependencies")))
                if len(candidates) >= 10_000:
                    break
    for path, raw in candidates:
        if not isinstance(path, str) or not isinstance(raw, dict):
            continue
        name = _lock_name(path)
        version = raw.get("version")
        if name is None or not isinstance(version, str) or not version:
            continue
        result.append(_LockedPackage(
            path=path[:1_000],
            name=name[:300],
            version=version[:200],
            resolved=raw.get("resolved")[:2_000] if isinstance(raw.get("resolved"), str) else None,
            integrity=raw.get("integrity")[:2_000] if isinstance(raw.get("integrity"), str) else None,
            dev=raw.get("dev") is True,
            optional=raw.get("optional") is True,
            has_install_script=raw.get("hasInstallScript") is True,
        ))
    return result


def _purl(name: str, version: str) -> tuple[str | None, str, str]:
    if name.startswith("@") and "/" in name:
        group, package_name = name[1:].split("/", 1)
        value = f"pkg:npm/%40{quote(group, safe='')}/{quote(package_name, safe='')}@{quote(version, safe='.-_')}"
        return group, package_name, value
    return None, name, f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='.-_')}"


def _integrity_hash(value: str | None) -> CycloneDxHash | None:
    if not value:
        return None
    for candidate in value.split():
        if "-" not in candidate:
            continue
        algorithm, encoded = candidate.split("-", 1)
        algorithm = algorithm.lower()
        if algorithm not in _SUPPORTED_INTEGRITY:
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(decoded) == _EXPECTED_HASH_BYTES[algorithm]:
            return CycloneDxHash(alg=_SUPPORTED_INTEGRITY[algorithm], content=decoded.hex())
    return None


def _component(package: _LockedPackage, lock_path: str) -> CycloneDxComponent:
    group, name, purl = _purl(package.name, package.version)
    digest = _integrity_hash(package.integrity)
    return CycloneDxComponent(
        bom_ref=purl,
        group=group,
        name=name,
        version=package.version,
        purl=purl,
        scope="excluded" if package.dev else "optional" if package.optional else "required",
        hashes=[digest] if digest else [],
        properties=[
            CycloneDxProperty(name="extension-xray:source-lockfile", value=lock_path),
            CycloneDxProperty(name="extension-xray:lock-path", value=package.path),
        ],
    )


def _levenshtein_one(left: str, right: str) -> bool:
    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    if len(left) == len(right):
        differences = [
            index
            for index, (left_char, right_char) in enumerate(zip(left, right, strict=True))
            if left_char != right_char
        ]
        if len(differences) == 1:
            return True
        return (
            len(differences) == 2
            and differences[1] == differences[0] + 1
            and left[differences[0]] == right[differences[1]]
            and left[differences[1]] == right[differences[0]]
        )
    for index in range(len(right)):
        if left == right[:index] + right[index + 1:]:
            return True
    return False


def _typo_target(name: str) -> str | None:
    candidate = name.rsplit("/", 1)[-1].lower()
    return next(
        (
            popular
            for popular in sorted(_POPULAR_NPM_PACKAGES)
            if candidate[:1] == popular[:1] and _levenshtein_one(candidate, popular)
        ),
        None,
    )


def _database_path(settings: SupplyChainSettings) -> Path:
    return settings.advisory_database or Path(__file__).with_name("data") / "osv-advisories.json"


def _load_advisories(settings: SupplyChainSettings) -> tuple[AdvisoryDatabaseStatus, list[dict[str, Any]], list[str]]:
    path = _database_path(settings)
    limitations: list[str] = []
    try:
        size = path.stat().st_size
        if size > settings.max_advisory_bytes:
            raise ValueError("database exceeds configured size limit")
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, list):
            raw_records = document
            metadata: dict[str, Any] = {
                "source": "Operator-provided OSV JSON list",
                "coverage": "Coverage and freshness depend on the configured XRAY_ADVISORY_DB file.",
            }
        elif isinstance(document, dict) and isinstance(document.get("advisories"), list):
            raw_records = document["advisories"]
            metadata = document
        else:
            raise ValueError("database format is invalid")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        message = f"Offline advisory database unavailable: {str(error)[:200]}."
        limitations.append(message)
        return AdvisoryDatabaseStatus(available=False, message=message), [], limitations
    selected_records = raw_records[:settings.max_advisories]
    records = [item for item in selected_records if isinstance(item, dict)]
    if len(raw_records) > settings.max_advisories:
        limitations.append(f"Offline advisory records were capped at {settings.max_advisories} entries.")
    if len(records) < len(selected_records):
        limitations.append("Malformed non-object advisory records were ignored.")
    coverage = metadata.get("coverage") if isinstance(metadata.get("coverage"), str) else None
    message = "Offline advisory snapshot loaded; results are limited to its declared coverage and date."
    if coverage:
        limitations.append(f"Advisory coverage: {coverage}")
    return AdvisoryDatabaseStatus(
        available=True,
        source=metadata.get("source") if isinstance(metadata.get("source"), str) else None,
        snapshot_date=metadata.get("snapshot_date") if isinstance(metadata.get("snapshot_date"), str) else None,
        coverage=coverage,
        record_count=len(records),
        message=message,
    ), records, limitations


def _range_affected(version: str, ranges: Any) -> tuple[bool, str | None]:
    current = _semver(version)
    if current is None or not isinstance(ranges, list):
        return False, None
    for raw_range in ranges:
        if not isinstance(raw_range, dict) or raw_range.get("type") != "SEMVER":
            continue
        events = raw_range.get("events")
        if not isinstance(events, list):
            continue
        affected = False
        fixed_version: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if isinstance(event.get("introduced"), str):
                introduced = _semver(event["introduced"])
                if event["introduced"] == "0" or (introduced and current >= introduced):
                    affected = True
            elif isinstance(event.get("fixed"), str):
                fixed = _semver(event["fixed"])
                if fixed and current >= fixed:
                    affected = False
                elif fixed and affected:
                    fixed_version = event["fixed"][:200]
            elif isinstance(event.get("last_affected"), str):
                last = _semver(event["last_affected"])
                if last and current > last:
                    affected = False
            elif isinstance(event.get("limit"), str):
                limit = _semver(event["limit"])
                if limit and current >= limit:
                    affected = False
        if affected:
            return True, fixed_version
    return False, None


def _advisory_match(package: _LockedPackage, record: dict[str, Any]) -> AdvisoryMatch | None:
    if record.get("withdrawn"):
        return None
    advisory_id = record.get("id")
    if not isinstance(advisory_id, str) or not advisory_id:
        return None
    affected_entries = record.get("affected")
    if not isinstance(affected_entries, list):
        return None
    for affected in affected_entries:
        if not isinstance(affected, dict) or not isinstance(affected.get("package"), dict):
            continue
        identity = affected["package"]
        if identity.get("ecosystem") != "npm" or identity.get("name") != package.name:
            continue
        versions = affected.get("versions")
        matched = isinstance(versions, list) and package.version in versions
        range_match, fixed_version = _range_affected(package.version, affected.get("ranges"))
        if not matched and not range_match:
            continue
        database_specific = record.get("database_specific")
        raw_severity = (
            database_specific.get("severity")
            if isinstance(database_specific, dict) and isinstance(database_specific.get("severity"), str)
            else "HIGH"
        ).lower()
        severity = {
            "critical": Severity.critical,
            "high": Severity.high,
            "moderate": Severity.medium,
            "medium": Severity.medium,
            "low": Severity.low,
        }.get(raw_severity, Severity.high)
        aliases = [item[:200] for item in record.get("aliases", [])[:50] if isinstance(item, str)] if isinstance(record.get("aliases"), list) else []
        summary = record.get("summary") if isinstance(record.get("summary"), str) else advisory_id
        return AdvisoryMatch(
            advisory_id=advisory_id[:200],
            aliases=aliases,
            package=package.name,
            version=package.version,
            severity=severity,
            summary=summary[:1_000],
            fixed_version=fixed_version,
            reference=f"https://osv.dev/vulnerability/{quote(advisory_id, safe='-')}"[:2_000],
        )
    return None


def analyze_supply_chain(
    root: Path,
    files: list[FileEntry],
    *,
    serial: uuid.UUID,
    archive_limits: ArchiveLimits,
    settings: SupplyChainSettings | None = None,
) -> SupplyChainResult:
    active_settings = settings or SupplyChainSettings.from_env()
    package_entry = _shallowest(files, "package.json")
    lock_entry = _shallowest(files, "package-lock.json")
    package, package_text = _read_json(root, package_entry, archive_limits.max_metadata_bytes)
    lock, lock_text = _read_json(root, lock_entry, archive_limits.max_metadata_bytes)
    direct = _direct_dependencies(package)
    locked = _locked_packages(lock)
    findings: list[Finding] = []
    limitations: list[str] = []
    package_path = package_entry.path if package_entry else "package.json"
    lock_path = lock_entry.path if lock_entry else "package-lock.json"

    if direct and lock_entry is None:
        _append(findings, _finding(
            rule_id="SCM-LOCK-000", title="Declared dependencies have no npm lockfile",
            severity=Severity.high, confidence=Confidence.high,
            description="package.json declares dependencies but no package-lock.json was admitted.",
            impact="Dependency versions and artifact integrity are not reproducibly pinned for npm.",
            guidance="Generate and review a package-lock.json with a trusted npm version, then commit it.",
            path=package_path, text=package_text, offset=max(package_text.find('"dependencies"'), 0),
            tags=("supply-chain", "lockfile"), summary="Dependencies are declared without package-lock.json.",
        ))

    locked_by_name: dict[str, _LockedPackage] = {}
    for item in sorted(locked, key=lambda package: (len(PurePosixPath(package.path).parts), package.path)):
        locked_by_name.setdefault(item.name, item)
    for name, (specifier, _scope) in direct.items():
        offset = max(package_text.find(json.dumps(name)), 0)
        locked_package = locked_by_name.get(name)
        if locked_package is None and lock_entry is not None:
            _append(findings, _finding(
                rule_id="SCM-LOCK-001", title="Direct dependency is missing from lockfile",
                severity=Severity.high, confidence=Confidence.high,
                description="A package.json dependency has no matching package-lock entry.",
                impact="Install results may diverge from the reviewed dependency graph.",
                guidance="Regenerate the lockfile in a trusted environment and review the resulting diff.",
                path=package_path, text=package_text, offset=offset,
                tags=("supply-chain", "lockfile"), summary=f"{name!r} is declared but not locked.",
            ))
        exact = _semver(specifier)
        if locked_package and exact and _semver(locked_package.version) != exact:
            _append(findings, _finding(
                rule_id="SCM-LOCK-002", title="Exact dependency version disagrees with lockfile",
                severity=Severity.high, confidence=Confidence.high,
                description="An exact package.json version differs from the resolved lockfile version.",
                impact="The reviewed manifest and installed dependency graph do not describe the same artifact.",
                guidance="Resolve the mismatch and regenerate the lockfile using a trusted package manager.",
                path=package_path, text=package_text, offset=offset,
                tags=("supply-chain", "lockfile"),
                summary=f"{name} declares {specifier} but locks {locked_package.version}.",
            ))
        if _NON_REGISTRY_SPEC.search(specifier):
            _append(findings, _finding(
                rule_id="SCM-NPM-002", title="Direct dependency uses a non-registry source",
                severity=Severity.high, confidence=Confidence.high,
                description="A direct npm dependency is sourced from Git, a URL, workspace, file, or link specifier.",
                impact="The artifact may bypass registry integrity, review, provenance, or normal update controls.",
                guidance="Pin a reviewed immutable commit or artifact digest and document why the registry is bypassed.",
                path=package_path, text=package_text, offset=offset,
                tags=("supply-chain", "npm", "provenance"), summary=f"{name!r} uses {specifier[:200]!r}.",
            ))
        if target := _typo_target(name):
            _append(findings, _finding(
                rule_id="SCM-TYPO-001", title="Dependency name resembles a popular package",
                severity=Severity.medium, confidence=Confidence.low,
                description="A direct dependency is one edit away from a curated popular npm package name.",
                impact="A mistyped or deceptive package name may introduce attacker-controlled code.",
                guidance="Verify the exact package owner, registry page, repository, and intended spelling.",
                path=package_path, text=package_text, offset=offset,
                tags=("supply-chain", "typosquatting", "npm"), summary=f"{name!r} resembles {target!r}.",
            ))

    integrity_count = 0
    missing_integrity_count = 0
    external_source_count = 0
    install_script_count = 0
    for package_item in locked:
        offset = max(lock_text.find(json.dumps(package_item.path)), lock_text.find(json.dumps(package_item.name)), 0)
        if _integrity_hash(package_item.integrity):
            integrity_count += 1
        else:
            missing_integrity_count += 1
            _append(findings, _finding(
                rule_id="SCM-LOCK-003", title="Locked package lacks valid strong integrity",
                severity=Severity.medium, confidence=Confidence.high,
                description="A package-lock entry has no valid SHA-256, SHA-384, or SHA-512 SRI digest.",
                impact="The downloaded artifact cannot be checked against a strong lockfile digest by this analyzer.",
                guidance="Regenerate the lockfile from the expected registry and review any integrity changes.",
                path=lock_path, text=lock_text, offset=offset,
                tags=("supply-chain", "integrity", "lockfile"),
                summary=f"{package_item.name}@{package_item.version} has no valid strong integrity value.",
            ))
        if package_item.resolved:
            host = (urlparse(package_item.resolved).hostname or "").lower()
            if host and host not in _ALLOWED_REGISTRY_HOSTS:
                external_source_count += 1
                _append(findings, _finding(
                    rule_id="SCM-PROV-001", title="Locked package resolves outside the standard npm registry",
                    severity=Severity.high, confidence=Confidence.high,
                    description="A package-lock entry resolves from a host outside the recognized npm/yarn registry hosts.",
                    impact="A private mirror, compromised host, or direct artifact URL controls the installed bytes.",
                    guidance="Verify the host, TLS ownership, immutability, artifact digest, and organizational registry policy.",
                    path=lock_path, text=lock_text, offset=offset,
                    tags=("supply-chain", "provenance", "registry"),
                    summary=f"{package_item.name}@{package_item.version} resolves from {host!r}.",
                ))
        if package_item.has_install_script:
            install_script_count += 1
            _append(findings, _finding(
                rule_id="SCM-NPM-001", title="Locked dependency declares an install script",
                severity=Severity.medium, confidence=Confidence.high,
                description="The lockfile marks a dependency as having an install-time script.",
                impact="Installing dependencies may execute package-controlled code with developer or CI privileges.",
                guidance="Inspect the exact package version and script before installation; consider --ignore-scripts during review.",
                path=lock_path, text=lock_text, offset=offset,
                tags=("supply-chain", "npm", "install-script"),
                summary=f"{package_item.name}@{package_item.version} is marked hasInstallScript.",
            ))

    advisory_status, advisories, advisory_limitations = _load_advisories(active_settings)
    limitations.extend(advisory_limitations)
    advisory_matches: list[AdvisoryMatch] = []
    for package_item in locked:
        for record in advisories:
            match = _advisory_match(package_item, record)
            if match is None:
                continue
            advisory_matches.append(match)
            offset = max(lock_text.find(json.dumps(package_item.path)), 0)
            _append(findings, _finding(
                rule_id="SCM-ADV-001", title="Offline advisory matches locked dependency",
                severity=match.severity, confidence=Confidence.high,
                description="A locked package and version match an entry in the configured offline OSV snapshot.",
                impact="The dependency may contain a publicly disclosed vulnerability within the snapshot coverage.",
                guidance=(
                    f"Review {match.advisory_id} and upgrade to {match.fixed_version or 'a verified unaffected version'}. "
                    "Refresh the offline database before making release decisions."
                ),
                path=lock_path, text=lock_text, offset=offset,
                tags=("supply-chain", "advisory", "osv"),
                summary=f"{match.advisory_id} matches {match.package}@{match.version}.",
            ))

    unique_components: dict[str, CycloneDxComponent] = {}
    for package_item in locked:
        component = _component(package_item, lock_path)
        unique_components.setdefault(component.purl, component)
    all_components = sorted(unique_components.values(), key=lambda item: item.purl.casefold())
    components = all_components[:active_settings.max_components]
    if len(all_components) > len(components):
        limitations.append(f"CycloneDX components were capped at {active_settings.max_components} entries.")

    sbom = CycloneDxBom(
        serial_number=f"urn:uuid:{serial}",
        components=components,
    )
    lockfile_version = lock.get("lockfileVersion") if isinstance(lock.get("lockfileVersion"), int) else None
    summary = SupplyChainSummary(
        component_count=len(components),
        direct_dependency_count=len(direct),
        lockfile=LockfileIntegritySummary(
            path=lock_entry.path if lock_entry else None,
            lockfile_version=lockfile_version,
            package_count=len(locked),
            integrity_count=integrity_count,
            missing_integrity_count=missing_integrity_count,
            external_source_count=external_source_count,
            install_script_count=install_script_count,
        ),
        advisory_database=advisory_status,
        advisory_matches=advisory_matches[:500],
    )
    if len(advisory_matches) > 500:
        limitations.append("Advisory matches were capped at 500 results.")
    if len(findings) >= _MAX_FINDINGS:
        limitations.append(f"Supply-chain findings were capped at {_MAX_FINDINGS} results.")
    return SupplyChainResult(
        sbom=sbom,
        summary=summary,
        findings=findings,
        limitations=limitations,
    )
