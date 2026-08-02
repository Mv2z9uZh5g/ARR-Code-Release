from __future__ import annotations

import hashlib
import ipaddress
import re
import string
from dataclasses import dataclass
from typing import Iterable, Pattern

from models import Finding


SECRET_CONTEXT = re.compile(
    r"(?i)(aws|secret|token|api[_-]?key|password|passwd|pwd|credential|private|auth|bearer|client_secret|anthropic|openai|github|huggingface|hf)"
)


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: Pattern[str]
    confidence: float
    explanation: str
    group: int | str = 0
    requires_context: bool = False


RULES: tuple[Rule, ...] = (
    Rule("aws_access_key_id", "cloud_credential", re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"), 0.98, "AWS access key identifier"),
    Rule("anthropic_api_key", "api_token", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0.98, "Anthropic API key format"),
    Rule("github_token", "api_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}\b"), 0.98, "GitHub token format"),
    Rule("slack_token", "api_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.98, "Slack token format"),
    Rule("google_api_key", "api_token", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.96, "Google API key format"),
    Rule("openai_api_key", "api_token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), 0.96, "OpenAI-style API key format"),
    Rule("huggingface_token", "api_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), 0.96, "HuggingFace token format"),
    Rule("jwt", "api_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0.9, "JWT-like bearer credential"),
    Rule("private_key_block", "private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{20,}?-----END [A-Z0-9 ]*PRIVATE KEY-----"), 0.99, "PEM private key block"),
    Rule("ssh_private_key", "private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{20,}?-----END OPENSSH PRIVATE KEY-----"), 0.99, "OpenSSH private key block"),
    Rule("database_url", "database_credential", re.compile(r"\b(?:postgres|postgresql|mysql|mariadb|mongodb|redis)://[^\s'\"<>]+", re.I), 0.94, "Database connection URL"),
    Rule("bearer_token", "api_token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})"), 0.86, "Bearer token assignment", 1),
    Rule("basic_auth_url", "credential", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@[^\s]+", re.I), 0.93, "URL containing basic auth credentials"),
    Rule("password_assignment", "credential", re.compile(r"(?i)\b(?:password|passwd|pwd|pass|db_password)\b\s*[:=]\s*['\"]?([^'\"\s#]{6,})"), 0.88, "Password-like assignment", 1),
    Rule("api_key_assignment", "api_token", re.compile(r"(?i)\b(?:api[_-]?key|token|secret|client_secret|access_token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{12,})"), 0.84, "Secret-like assignment", 1),
    Rule("sensitive_env_assignment", "api_token", re.compile(r"(?i)\b(?:export\s+)?[A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|CLIENT_SECRET|ACCESS_TOKEN)[A-Z0-9_]*\s*[:=]\s*['\"]?([A-Za-z0-9._~+/=-]{12,})"), 0.86, "Sensitive environment variable assignment", 1),
    Rule("aws_secret_like", "cloud_credential", re.compile(r"(?i)\baws[_-]?(?:secret|secret_access_key)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{32,})"), 0.94, "AWS secret-like value near AWS label", 1),
    Rule("email", "pii", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.65, "Email address"),
    Rule("phone_number", "pii", re.compile(r"(?<![A-Za-z0-9])(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?![A-Za-z0-9])"), 0.55, "Phone-number-like value"),
    Rule("ssn", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.8, "SSN-like synthetic PII"),
    Rule("credit_card", "pii", re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0.75, "Credit-card-like value passing Luhn validation"),
    Rule("ip_address", "network_identifier", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.45, "IPv4 address"),
)


def scan_text(
    text: str,
    relative_path: str,
    *,
    include_raw_values: bool = False,
    source: str = "regex",
    discovery_source: str | None = None,
    base_offset: int | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    line_starts = _line_starts(text)

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group)
            if not _valid_match(rule.name, value, match, text):
                continue
            start = match.start(rule.group if isinstance(rule.group, int) else 0)
            line = _line_for_offset(line_starts, start)
            absolute_offset = None if base_offset is None else base_offset + start
            evidence = _snippet(text, match.start(), match.end(), value)
            finding = build_finding(
                type_name=rule.name,
                category=rule.category,
                relative_path=relative_path,
                value=value,
                line=line,
                offset=absolute_offset,
                confidence=rule.confidence,
                source=source,
                discovery_source=discovery_source or _default_discovery_source(source),
                evidence=evidence,
                explanation=rule.explanation,
                include_raw_values=include_raw_values,
            )
            findings.append(finding)

    return findings


def scan_shell_history(text: str, relative_path: str, include_raw_values: bool = False, discovery_source: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if not SECRET_CONTEXT.search(line):
            continue
        if re.search(r"(?i)\b(export|curl|wget|docker login|psql|mysql|aws configure|kubectl)\b", line):
            redacted = SECRET_CONTEXT.sub(lambda m: m.group(0), redact_secret(line))
            findings.append(
                build_finding(
                    "shell_history_secret",
                    "credential",
                    relative_path,
                    line.strip(),
                    idx,
                    None,
                    0.72,
                    "heuristic",
                    redacted,
                    "Shell history command appears to expose secret material",
                    include_raw_values,
                    discovery_source or "regex_direct",
                )
            )
    return findings


def scan_structured_heuristics(text: str, relative_path: str, include_raw_values: bool = False, discovery_source: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    lower_path = relative_path.lower()
    if "kube" in lower_path or "kubeconfig" in lower_path:
        for key in ("client-key-data", "token", "password"):
            pattern = re.compile(rf"(?im)^\s*{re.escape(key)}\s*:\s*([^\s#]+)")
            for match in pattern.finditer(text):
                if "$" in match.group(1) or "{" in match.group(1):
                    continue
                findings.append(
                    build_finding("kubeconfig_credential", "cloud_credential", relative_path, match.group(1), _line_for_offset(_line_starts(text), match.start(1)), None, 0.9, "heuristic", _snippet(text, match.start(), match.end(), match.group(1)), "kubeconfig credential field", include_raw_values, discovery_source or "regex_direct")
                )
    if "docker" in lower_path and "auth" in text:
        for match in re.finditer(r'"auth"\s*:\s*"([^"]{8,})"', text):
            findings.append(
                build_finding("docker_auth", "credential", relative_path, match.group(1), _line_for_offset(_line_starts(text), match.start(1)), None, 0.9, "heuristic", _snippet(text, match.start(), match.end(), match.group(1)), "Docker auth config entry", include_raw_values, discovery_source or "regex_direct")
            )
    if "history" in lower_path:
        findings.extend(scan_shell_history(text, relative_path, include_raw_values, discovery_source))
    return findings


def scan_contextual_person_names(
    text: str,
    relative_path: str,
    include_raw_values: bool = False,
    source: str = "llm_contextual_inference",
    discovery_source: str = "llm_contextual_inference",
) -> list[Finding]:
    findings: list[Finding] = []
    line_starts = _line_starts(text)
    name_assignment = re.compile(
        r"(?im)\b(?:customer|client|employee|owner|contact|user)?[_ -]?(?:full[_ -]?)?name\b\s*[:=]\s*['\"]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?"
    )
    for match in name_assignment.finditer(text):
        value = match.group(1).strip()
        findings.append(
            build_finding(
                "person_name",
                "pii",
                relative_path,
                value,
                _line_for_offset(line_starts, match.start(1)),
                None,
                0.72,
                source,
                _snippet(text, match.start(), match.end(), value),
                "Contextual person-name field in synthetic PII bundle",
                include_raw_values,
                discovery_source,
            )
        )
    return findings


def extract_printable_strings(data: bytes, min_length: int = 5) -> list[tuple[int, str]]:
    allowed = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    results: list[tuple[int, str]] = []
    start: int | None = None
    buf = bytearray()
    for idx, byte in enumerate(data):
        if byte in allowed and byte not in (0x00,):
            if start is None:
                start = idx
            buf.append(byte)
        else:
            if start is not None and len(buf) >= min_length:
                results.append((start, buf.decode("utf-8", errors="ignore")))
            start = None
            buf = bytearray()
    if start is not None and len(buf) >= min_length:
        results.append((start, buf.decode("utf-8", errors="ignore")))
    return results


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return non_text / max(len(sample), 1) > 0.25


def build_finding(
    type_name: str,
    category: str,
    relative_path: str,
    value: str,
    line: int | None,
    offset: int | None,
    confidence: float,
    source: str,
    evidence: str,
    explanation: str,
    include_raw_values: bool = False,
    discovery_source: str = "regex_direct",
) -> Finding:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    redacted = redact_secret(value)
    finding_id = hashlib.sha256(f"{type_name}:{relative_path}:{digest}:{line}:{offset}".encode()).hexdigest()[:16]
    return Finding(
        finding_id=finding_id,
        type=type_name,
        category=category,
        relative_path=relative_path,
        line=line,
        offset=offset,
        redacted_value=redacted,
        raw_value=value if include_raw_values else None,
        full_value_sha256=digest,
        confidence=round(float(confidence), 3),
        source=source,
        discovery_source=discovery_source,
        evidence=evidence,
        explanation=explanation,
    )


def redact_secret(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 10:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return value[:4] + "*" * min(24, max(6, len(value) - 8)) + value[-4:]


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    by_key: dict[tuple[str, str], Finding] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        key = (finding.full_value_sha256, finding.relative_path)
        previous = by_key.get(key)
        if previous is None:
            by_key[key] = finding
            order.append(key)
            continue
        if finding.confidence > previous.confidence:
            by_key[key] = finding
    return [by_key[key] for key in order]


def _valid_match(rule_name: str, value: str, match: re.Match[str], text: str) -> bool:
    if rule_name == "credit_card":
        digits = re.sub(r"\D", "", value)
        return 13 <= len(digits) <= 19 and luhn_valid(digits)
    if rule_name == "ip_address":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if rule_name in {"api_key_assignment", "password_assignment"}:
        window = text[max(0, match.start() - 80) : min(len(text), match.end() + 80)]
        return bool(SECRET_CONTEXT.search(window))
    return True


def luhn_valid(digits: str) -> bool:
    total = 0
    reverse_digits = list(map(int, reversed(digits)))
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer("\n", text))
    return starts


def _line_for_offset(line_starts: list[int], offset: int) -> int:
    line = 1
    for idx, start in enumerate(line_starts, start=1):
        if start > offset:
            break
        line = idx
    return line


def _snippet(text: str, start: int, end: int, value: str, radius: int = 80) -> str:
    snippet = text[max(0, start - radius) : min(len(text), end + radius)]
    snippet = snippet.replace(value, redact_secret(value))
    return redact_evidence(snippet).replace("\n", "\\n")


def redact_evidence(snippet: str) -> str:
    """Redact obvious neighboring secret assignments inside evidence context."""
    assignment = re.compile(
        r"(?i)(\b(?:password|passwd|pwd|pass|api[_-]?key|token|secret|client_secret|access_token|aws_secret_access_key)\b\s*[:=]\s*['\"]?)([^'\"\s#]{6,})"
    )
    bearer = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{12,})")
    snippet = assignment.sub(lambda m: m.group(1) + redact_secret(m.group(2)), snippet)
    snippet = bearer.sub(lambda m: m.group(1) + redact_secret(m.group(2)), snippet)
    return snippet


def _default_discovery_source(source: str) -> str:
    if source == "binary_strings":
        return "binary_strings"
    if source == "heuristic_decode":
        return "heuristic_decode"
    if source == "llm_fragment_join":
        return "llm_fragment_join"
    if source == "llm_contextual_inference":
        return "llm_contextual_inference"
    if source == "llm_prioritized_scan":
        return "llm_prioritized_scan"
    return "regex_direct"
