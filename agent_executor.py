from __future__ import annotations

import base64
import binascii
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from models import FileRecord, Finding, ScanConfig
from safe_fs import SafeFS, path_priority
from scanners import (
    build_finding,
    deduplicate_findings,
    extract_printable_strings,
    looks_binary,
    scan_contextual_person_names,
    scan_structured_heuristics,
    redact_evidence,
    redact_secret,
    scan_text,
)


ALLOWED_ACTIONS = {
    "list_dir",
    "read_file",
    "search_text",
    "extract_strings",
    "build_symbol_table",
    "resolve_expression",
    "resolve_env_reference",
    "reconstruct_candidate",
    "join_fragments",
    "decode_candidate",
    "inspect_snippet",
    "classify_candidate",
    "prioritize_paths",
}


@dataclass
class ActionResult:
    action: str
    ok: bool
    observation: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_trace(self) -> dict[str, Any]:
        data = {
            "action": self.action,
            "ok": self.ok,
            "observation": self.observation,
            "findings_count": len(self.findings),
        }
        if self.error:
            data["error"] = self.error
        return data


class BoundedActionExecutor:
    """Validated, read-only executor for LLM-proposed agent actions."""

    def __init__(self, fs: SafeFS, inventory: list[FileRecord], config: ScanConfig):
        self.fs = fs
        self.config = config
        self.records_by_path = {record.relative_path: record for record in inventory}
        self.symbol_tables: dict[str, dict[str, str]] = {}

    def execute(self, action: dict[str, Any]) -> ActionResult:
        if not isinstance(action, dict):
            return self._error("invalid", "action must be an object")
        name = str(action.get("action") or "")
        if name not in ALLOWED_ACTIONS:
            return self._error(name or "missing", "action is not allowed")
        try:
            if name == "list_dir":
                return self._list_dir(action)
            if name == "read_file":
                return self._read_file(action)
            if name == "search_text":
                return self._search_text(action)
            if name == "extract_strings":
                return self._extract_strings(action)
            if name == "build_symbol_table":
                return self._build_symbol_table(action)
            if name == "resolve_expression":
                return self._resolve_expression(action)
            if name == "resolve_env_reference":
                return self._resolve_env_reference(action)
            if name == "reconstruct_candidate":
                return self._reconstruct_candidate(action)
            if name == "join_fragments":
                return self._join_fragments(action)
            if name == "decode_candidate":
                return self._decode_candidate(action)
            if name == "inspect_snippet":
                return self._inspect_snippet(action)
            if name == "classify_candidate":
                return self._classify_candidate(action)
            if name == "prioritize_paths":
                return self._prioritize_paths(action)
        except Exception as exc:
            return self._error(name, f"{exc.__class__.__name__}: {exc}")
        return self._error(name, "unhandled action")

    def _list_dir(self, action: dict[str, Any]) -> ActionResult:
        rel_path = _clean_rel_path(action.get("path", "."))
        path = self.fs.resolve_under_root(rel_path)
        if not path.is_dir():
            return self._error("list_dir", "path is not a directory")
        entries: list[dict[str, Any]] = []
        for child in sorted(path.iterdir(), key=lambda p: p.name)[:100]:
            rel = self.fs.relative(child)
            try:
                st = child.lstat()
            except OSError:
                continue
            entry_type = "file" if stat.S_ISREG(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "special"
            if child.is_symlink():
                try:
                    self.fs.resolve_under_root(child)
                    entry_type = "symlink"
                except Exception:
                    entry_type = "symlink_escape"
            entries.append({"name": child.name, "relative_path": rel, "type": entry_type, "size": st.st_size, "priority": path_priority(rel)})
        return ActionResult("list_dir", True, {"path": rel_path, "entries": entries, "truncated": len(entries) >= 100})

    def _read_file(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "read_file")
        max_bytes = _bounded_int(action.get("max_bytes"), 4096, 1, self.config.max_file_size)
        data = self.fs.read_bytes_limited(record, min(max_bytes, self.config.max_file_size))
        text = data.decode("utf-8", errors="replace")
        findings = scan_text(
            text,
            record.relative_path,
            include_raw_values=self.config.include_raw_values,
            source="llm_prioritized_scan",
            discovery_source="llm_prioritized_scan",
        )
        return ActionResult(
            "read_file",
            True,
            {
                "path": record.relative_path,
                "bytes_read": len(data),
                "truncated": record.size > len(data),
                "snippet": _redacted_limited(text, 4000),
            },
            deduplicate_findings(findings),
        )

    def _search_text(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "search_text")
        query = str(action.get("regex") or action.get("keyword") or "")[:200]
        if not query:
            return self._error("search_text", "regex or keyword is required")
        data = self.fs.read_bytes_limited(record, self.config.max_file_size)
        text = data.decode("utf-8", errors="replace")
        matches: list[dict[str, Any]] = []
        try:
            pattern = re.compile(query)
        except re.error:
            pattern = re.compile(re.escape(query), re.I)
        line_starts = _line_starts(text)
        findings: list[Finding] = []
        for match in pattern.finditer(text):
            if len(matches) >= 50:
                break
            line = _line_for_offset(line_starts, match.start())
            snippet = text[max(0, match.start() - 120) : min(len(text), match.end() + 120)]
            matches.append({"line": line, "snippet": _redacted_limited(snippet, 500)})
            findings.extend(
                scan_text(
                    snippet,
                    record.relative_path,
                    include_raw_values=self.config.include_raw_values,
                    source="llm_prioritized_scan",
                    discovery_source="llm_prioritized_scan",
                )
            )
        return ActionResult(
            "search_text",
            True,
            {"path": record.relative_path, "matches": matches, "truncated": len(matches) >= 50},
            deduplicate_findings(findings),
        )

    def _extract_strings(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "extract_strings")
        min_length = _bounded_int(action.get("min_length"), 5, 3, 80)
        data = self.fs.read_bytes_limited(record, min(record.size, self.config.max_binary_extract_size))
        strings = extract_printable_strings(data, min_length)
        findings: list[Finding] = []
        observed: list[dict[str, Any]] = []
        for offset, value in strings[:200]:
            observed.append({"offset": offset, "value": _redacted_limited(value, 300)})
            findings.extend(
                scan_text(
                    value,
                    record.relative_path,
                    include_raw_values=self.config.include_raw_values,
                    source="binary_strings",
                    discovery_source="binary_strings",
                    base_offset=offset,
                )
            )
        return ActionResult("extract_strings", True, {"path": record.relative_path, "strings": observed, "truncated": len(strings) > 200}, deduplicate_findings(findings))

    def _build_symbol_table(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "build_symbol_table")
        text = self.fs.read_bytes_limited(record, self.config.max_file_size).decode("utf-8", errors="replace")
        symbols = build_symbol_table(text)
        self.symbol_tables[record.relative_path] = symbols
        resolved_sensitive: list[dict[str, Any]] = []
        findings: list[Finding] = []
        for name, expression in _extract_named_expressions(text).items():
            if not SECRET_CONTEXT_RE.search(name):
                continue
            resolved = resolve_expression_value(expression, symbols, os.environ)
            if not resolved or resolved == expression:
                continue
            resolved_sensitive.append({"name": name, "value": redact_secret(resolved)})
            findings.extend(
                scan_text(
                    resolved,
                    record.relative_path,
                    include_raw_values=self.config.include_raw_values,
                    source="llm_semantic_reconstruction",
                    discovery_source="llm_semantic_reconstruction",
                )
            )
            contextual = f"{name}={resolved}"
            findings.extend(
                scan_structured_heuristics(
                    f"{name}: {resolved}",
                    record.relative_path,
                    include_raw_values=self.config.include_raw_values,
                    discovery_source="llm_semantic_reconstruction",
                )
            )
            findings.extend(
                scan_text(
                    contextual,
                    record.relative_path,
                    include_raw_values=self.config.include_raw_values,
                    source="llm_semantic_reconstruction",
                    discovery_source="llm_semantic_reconstruction",
                )
            )
        return ActionResult(
            "build_symbol_table",
            True,
            {
                "path": record.relative_path,
                "symbols": {name: redact_secret(value) for name, value in sorted(symbols.items())[:200]},
                "symbol_count": len(symbols),
                "resolved_sensitive_assignments": resolved_sensitive[:50],
                "truncated": len(symbols) > 200 or len(resolved_sensitive) > 50,
            },
            deduplicate_findings(findings),
        )

    def _resolve_expression(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "resolve_expression")
        text = self.fs.read_bytes_limited(record, self.config.max_file_size).decode("utf-8", errors="replace")
        symbols = self.symbol_tables.get(record.relative_path) or build_symbol_table(text)
        self.symbol_tables[record.relative_path] = symbols
        expression = str(action.get("expression") or "")
        variable = action.get("variable")
        if not expression and isinstance(variable, str):
            expression = _extract_named_expressions(text).get(variable, symbols.get(variable, ""))
        if not expression:
            return self._error("resolve_expression", "expression or variable is required")
        resolved = resolve_expression_value(expression, symbols, os.environ)
        findings = scan_text(
            resolved,
            record.relative_path,
            include_raw_values=self.config.include_raw_values,
            source="llm_semantic_reconstruction",
            discovery_source="llm_semantic_reconstruction",
        )
        return ActionResult(
            "resolve_expression",
            True,
            {"path": record.relative_path, "expression": _redacted_limited(expression, 500), "resolved": redact_secret(resolved)},
            deduplicate_findings(findings),
        )

    def _resolve_env_reference(self, action: dict[str, Any]) -> ActionResult:
        reference = str(action.get("name") or action.get("variable") or action.get("reference") or "")
        reference = reference.strip("${} $")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", reference):
            return self._error("resolve_env_reference", "valid environment variable name is required")
        value = os.environ.get(reference)
        source = "os.environ"
        path = "<environment>"
        if value is None:
            source = "root_search"
            found = self._search_symbol_under_root(reference)
            if found is None:
                return ActionResult("resolve_env_reference", True, {"name": reference, "found": False}, [])
            path, value = found
        findings = scan_text(
            value,
            path,
            include_raw_values=self.config.include_raw_values,
            source="llm_env_resolution",
            discovery_source="llm_env_resolution",
        )
        if not findings and _looks_secret_by_context(value, reference):
            findings = [
                build_finding(
                    "env_resolved_secret_candidate",
                    "api_token",
                    path,
                    value,
                    None,
                    None,
                    0.7,
                    "llm_env_resolution",
                    redact_secret(value),
                    "Resolved environment reference produced a secret-like value",
                    self.config.include_raw_values,
                    "llm_env_resolution",
                )
            ]
        return ActionResult("resolve_env_reference", True, {"name": reference, "source": source, "path": path, "value": redact_secret(value)}, deduplicate_findings(findings))

    def _reconstruct_candidate(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "reconstruct_candidate")
        text = self.fs.read_bytes_limited(record, self.config.max_file_size).decode("utf-8", errors="replace")
        symbols = self.symbol_tables.get(record.relative_path) or build_symbol_table(text)
        self.symbol_tables[record.relative_path] = symbols
        candidates: list[dict[str, Any]] = []
        variable = action.get("variable")
        expression = str(action.get("expression") or "")
        if isinstance(variable, str):
            expression = _extract_named_expressions(text).get(variable, symbols.get(variable, expression))
        if expression:
            candidates.append({"strategy": "expression_resolution", "identifiers": [str(variable or "expression")], "value": resolve_expression_value(expression, symbols, os.environ)})
        variables = [str(v) for v in action.get("variables", []) if isinstance(v, str)][:20]
        if variables:
            candidates.append({"strategy": "listed_variables", "identifiers": variables, "value": "".join(symbols.get(var, os.environ.get(var, _strip_quotes(var))) for var in variables)})
        if not candidates:
            candidates.extend(reconstruct_candidates_from_text(text, symbols, os.environ))
        findings: list[Finding] = []
        observed: list[dict[str, Any]] = []
        for candidate in _dedupe_candidates(candidates)[:50]:
            value = candidate["value"]
            observed.append({"strategy": candidate["strategy"], "identifiers": candidate["identifiers"], "value": redact_secret(value)})
            found = scan_text(
                value,
                record.relative_path,
                include_raw_values=self.config.include_raw_values,
                source="llm_semantic_reconstruction",
                discovery_source="llm_semantic_reconstruction",
            )
            if found:
                findings.extend(found)
            elif _looks_secret_by_context(value, " ".join(candidate["identifiers"])):
                findings.append(
                    build_finding(
                        "semantic_secret_candidate",
                        "api_token",
                        record.relative_path,
                        value,
                        None,
                        None,
                        0.72,
                        "llm_semantic_reconstruction",
                        redact_secret(value),
                        "Semantic reconstruction produced a secret-like value",
                        self.config.include_raw_values,
                        "llm_semantic_reconstruction",
                    )
                )
        return ActionResult("reconstruct_candidate", True, {"path": record.relative_path, "candidates": observed, "truncated": len(candidates) > 50}, deduplicate_findings(findings))

    def _join_fragments(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "join_fragments")
        text = self.fs.read_bytes_limited(record, self.config.max_file_size).decode("utf-8", errors="replace")
        variables = [str(v) for v in action.get("variables", []) if isinstance(v, str)][:12]
        candidates = join_fragment_candidates(text, variables)
        findings: list[Finding] = []
        observed: list[dict[str, Any]] = []
        for candidate in candidates[:50]:
            value = candidate["value"]
            observed.append({"strategy": candidate["strategy"], "identifiers": candidate["identifiers"], "value": redact_secret(value)})
            found = scan_text(
                value,
                record.relative_path,
                include_raw_values=self.config.include_raw_values,
                source="llm_fragment_join",
                discovery_source="llm_fragment_join",
            )
            if found:
                findings.extend(found)
            elif _looks_secret_by_context(value, " ".join(candidate["identifiers"])):
                findings.append(
                    build_finding(
                        "fragmented_secret_candidate",
                        "api_token",
                        record.relative_path,
                        value,
                        None,
                        None,
                        0.72,
                        "llm_fragment_join",
                        redact_secret(value),
                        "Joined fragments from LLM-proposed identifiers produced a secret-like value",
                        self.config.include_raw_values,
                        "llm_fragment_join",
                    )
                )
        return ActionResult("join_fragments", True, {"path": record.relative_path, "candidates": observed, "truncated": len(candidates) > 50}, deduplicate_findings(findings))

    def _decode_candidate(self, action: dict[str, Any]) -> ActionResult:
        encoding = str(action.get("encoding") or "").lower()
        value = str(action.get("value") or "")[:20000]
        if encoding not in {"base64", "hex", "urlencoding"}:
            return self._error("decode_candidate", "unsupported encoding")
        if not value:
            return self._error("decode_candidate", "value is required")
        decoded = decode_value(encoding, value)
        findings = scan_text(decoded, "<decoded_candidate>", include_raw_values=self.config.include_raw_values, source="heuristic_decode", discovery_source="heuristic_decode")
        if not findings and _looks_secret_by_context(decoded, encoding):
            findings = [
                build_finding(
                    "decoded_secret_candidate",
                    "api_token",
                    "<decoded_candidate>",
                    decoded,
                    None,
                    None,
                    0.68,
                    "heuristic_decode",
                    redact_secret(decoded),
                    f"Decoded {encoding} value appears secret-like",
                    self.config.include_raw_values,
                    "heuristic_decode",
                )
            ]
        return ActionResult("decode_candidate", True, {"encoding": encoding, "decoded": _redacted_limited(decoded, 1000)}, deduplicate_findings(findings))

    def _inspect_snippet(self, action: dict[str, Any]) -> ActionResult:
        record = self._record_for_action(action, "inspect_snippet")
        line_range = action.get("line_range") or action.get("lines") or []
        if not isinstance(line_range, list) or len(line_range) != 2:
            return self._error("inspect_snippet", "line_range must be [start, end]")
        start = _bounded_int(line_range[0], 1, 1, 1_000_000)
        end = _bounded_int(line_range[1], start + 20, start, min(start + 200, 1_000_000))
        text = self.fs.read_bytes_limited(record, self.config.max_file_size).decode("utf-8", errors="replace")
        lines = text.splitlines()
        snippet = "\n".join(lines[start - 1 : end])
        findings = scan_text(snippet, record.relative_path, include_raw_values=self.config.include_raw_values, source="llm_contextual_inference", discovery_source="llm_contextual_inference")
        return ActionResult("inspect_snippet", True, {"path": record.relative_path, "line_range": [start, end], "snippet": _redacted_limited(snippet, 2000)}, findings)

    def _classify_candidate(self, action: dict[str, Any]) -> ActionResult:
        snippet = str(action.get("candidate") or action.get("snippet") or "")[:4000]
        path = _clean_rel_path(action.get("path", "<candidate>"))
        if not snippet:
            return self._error("classify_candidate", "candidate snippet is required")
        findings = scan_text(snippet, path, include_raw_values=self.config.include_raw_values, source="llm_contextual_inference", discovery_source="llm_contextual_inference")
        findings.extend(
            scan_contextual_person_names(
                snippet,
                path,
                include_raw_values=self.config.include_raw_values,
                source="llm_contextual_inference",
                discovery_source="llm_contextual_inference",
            )
        )
        if not findings and SECRET_CONTEXT_RE.search(snippet):
            findings = [
                build_finding(
                    "contextual_secret_candidate",
                    "sensitive_data",
                    path,
                    snippet,
                    None,
                    None,
                    0.55,
                    "llm_contextual_inference",
                    _redacted_limited(snippet, 500),
                    "LLM-proposed candidate has sensitive context but no exact provider pattern",
                    self.config.include_raw_values,
                    "llm_contextual_inference",
                )
            ]
        return ActionResult("classify_candidate", True, {"path": path, "snippet": _redacted_limited(snippet, 1000)}, deduplicate_findings(findings))

    def _prioritize_paths(self, action: dict[str, Any]) -> ActionResult:
        candidates = action.get("candidate_paths") or action.get("paths") or []
        if not isinstance(candidates, list):
            return self._error("prioritize_paths", "candidate paths must be a list")
        allowed = []
        for path in candidates[:500]:
            if not isinstance(path, str):
                continue
            rel = _clean_rel_path(path)
            if rel in self.records_by_path:
                allowed.append({"path": rel, "priority": path_priority(rel)})
        allowed.sort(key=lambda item: (-item["priority"], item["path"]))
        return ActionResult("prioritize_paths", True, {"paths": allowed[:100], "truncated": len(allowed) > 100})

    def _search_symbol_under_root(self, reference: str) -> tuple[str, str] | None:
        for rel_path, record in sorted(self.records_by_path.items(), key=lambda item: (-path_priority(item[0]), item[0])):
            if record.size > self.config.max_file_size:
                continue
            try:
                data = self.fs.read_bytes_limited(record, min(record.size, self.config.max_file_size))
            except OSError:
                continue
            if looks_binary(data[:4096]):
                continue
            text = data.decode("utf-8", errors="replace")
            symbols = build_symbol_table(text)
            if reference in symbols:
                return rel_path, symbols[reference]
            expressions = _extract_named_expressions(text)
            if reference in expressions:
                return rel_path, resolve_expression_value(expressions[reference], symbols, os.environ)
        return None

    def _record_for_action(self, action: dict[str, Any], action_name: str) -> FileRecord:
        rel_path = _clean_rel_path(action.get("path"))
        if rel_path not in self.records_by_path:
            resolved = self.fs.resolve_under_root(rel_path)
            if not resolved.is_file():
                raise ValueError("path is not an inventoried regular file")
            stat_result = resolved.stat()
            return FileRecord(str(resolved), self.fs.relative(resolved), stat_result.st_size)
        record = self.records_by_path[rel_path]
        if record.size > max(self.config.max_file_size, self.config.max_binary_extract_size):
            raise ValueError(f"{action_name} rejected by size limit")
        return record

    def _error(self, action: str, message: str) -> ActionResult:
        return ActionResult(action, False, {}, [], message)


SECRET_CONTEXT_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|credential|anthropic|openai|github|huggingface|aws|bearer)")
ASSIGNMENT_RE = re.compile(r"""(?mx)
    ^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*
    (?P<quote>['"]?)(?P<value>.*?)(?P=quote)\s*$
""")
NAMED_EXPR_RE = re.compile(r"""(?mx)
    ^\s*(?:export\s+|(?:const|let|var)\s+)?
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*(?P<expr>.+?)\s*;?\s*$
""")
YAML_EXPR_RE = re.compile(r"""(?mx)
    ^\s*(?:-\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)
    \s*:\s*(?P<expr>.+?)\s*$
""")
ENV_LIST_EXPR_RE = re.compile(r"""(?mx)
    ^\s*-\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<expr>.+?)\s*$
""")
PY_STRING_ASSIGN_RE = re.compile(r"""(?m)^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"])(?P<value>.*?)(?P=quote)\s*$""")
PY_CONCAT_RE = re.compile(r"""(?m)^\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\+\s*[A-Za-z_][A-Za-z0-9_]*)+)\s*$""")
SHELL_VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
BRACE_VAR_REF_RE = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


def build_symbol_table(text: str) -> dict[str, str]:
    expressions = _extract_named_expressions(text)
    symbols: dict[str, str] = {}
    for _ in range(6):
        changed = False
        for name, expression in expressions.items():
            resolved = resolve_expression_value(expression, symbols, os.environ)
            if resolved and symbols.get(name) != resolved:
                symbols[name] = resolved
                changed = True
        if not changed:
            break
    return symbols


def resolve_expression_value(expression: str, symbols: dict[str, str], environ: dict[str, str] | os._Environ[str] | None = None) -> str:
    environ = environ or {}
    expr = expression.strip().rstrip(";").strip()
    if expr.startswith(("f'", 'f"', "F'", 'F"')):
        expr = expr[1:]
    parts = _split_concat(expr)
    if len(parts) > 1:
        return "".join(resolve_expression_value(part, symbols, environ) for part in parts)
    expr = _strip_quotes_or_template(expr)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr) and expr in symbols:
        return symbols[expr]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr) and expr in environ:
        return environ[expr]
    expr = _replace_refs(expr, symbols, environ)
    return expr


def reconstruct_candidates_from_text(text: str, symbols: dict[str, str], environ: dict[str, str] | os._Environ[str] | None = None) -> list[dict[str, Any]]:
    environ = environ or {}
    candidates: list[dict[str, Any]] = []
    for name, expression in _extract_named_expressions(text).items():
        if not _expression_needs_resolution(expression) and not SECRET_CONTEXT_RE.search(name):
            continue
        resolved = resolve_expression_value(expression, symbols, environ)
        if resolved and resolved != expression:
            candidates.append({"strategy": "semantic_expression", "identifiers": [name], "value": resolved})
    candidates.extend(join_fragment_candidates(text))
    return _dedupe_candidates(candidates)


def _extract_named_expressions(text: str) -> dict[str, str]:
    expressions: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        match = ENV_LIST_EXPR_RE.match(line) or NAMED_EXPR_RE.match(line)
        if match:
            expressions[match.group("name")] = _trim_inline_comment(match.group("expr"))
            continue
        yaml_match = YAML_EXPR_RE.match(line)
        if yaml_match:
            expression = _trim_inline_comment(yaml_match.group("expr"))
            if _is_simple_scalar_expression(expression) or _expression_needs_resolution(expression) or SECRET_CONTEXT_RE.search(yaml_match.group("name")):
                expressions[yaml_match.group("name").replace(".", "_").replace("-", "_")] = expression
    return expressions


def _expression_needs_resolution(expression: str) -> bool:
    return "$" in expression or "+" in expression or "`" in expression or bool(BRACE_VAR_REF_RE.search(expression))


def _is_simple_scalar_expression(expression: str) -> bool:
    expression = expression.strip()
    if not expression:
        return False
    if expression.startswith(("[", "{", "|", ">")):
        return False
    return len(expression) <= 500


def _split_concat(expression: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    for char in expression:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            current.append(char)
            quote = char
            continue
        if char == "+":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _strip_quotes_or_template(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'", "`"}:
        return value[1:-1]
    return value


def _replace_refs(value: str, symbols: dict[str, str], environ: dict[str, str] | os._Environ[str]) -> str:
    def resolve_name(name: str) -> str:
        return symbols.get(name, environ.get(name, ""))

    value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: resolve_name(m.group(1)), value)
    value = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: resolve_name(m.group(1)), value)
    value = BRACE_VAR_REF_RE.sub(lambda m: resolve_name(m.group(1)), value)
    return value


def _trim_inline_comment(value: str) -> str:
    quote: str | None = None
    escape = False
    for idx, char in enumerate(value):
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "#" and (idx == 0 or value[idx - 1].isspace()):
            return value[:idx].strip()
    return value.strip()


def join_fragment_candidates(text: str, variables: list[str] | None = None) -> list[dict[str, Any]]:
    assignments = _extract_string_assignments(text)
    candidates: list[dict[str, Any]] = []
    requested = variables or []
    if requested:
        parts = [assignments.get(var, _strip_quotes(var)) for var in requested]
        if all(parts):
            candidates.append({"strategy": "requested_identifiers", "identifiers": requested, "value": "".join(parts)})

    for line in text.splitlines():
        match = ASSIGNMENT_RE.match(line)
        if not match:
            continue
        value = _strip_quotes(match.group("value").strip())
        refs = SHELL_VAR_REF_RE.findall(value)
        if len(refs) >= 2 and all(ref in assignments for ref in refs):
            candidates.append({"strategy": "shell_variable_expansion", "identifiers": refs, "value": "".join(assignments[ref] for ref in refs)})

    for match in PY_CONCAT_RE.finditer(text):
        identifiers = [part.strip() for part in match.group("expr").split("+")]
        if len(identifiers) >= 2 and all(identifier in assignments for identifier in identifiers):
            candidates.append({"strategy": "python_string_concatenation", "identifiers": identifiers, "value": "".join(assignments[i] for i in identifiers)})

    names = sorted(assignments)
    for idx in range(len(names) - 1):
        group = names[idx : idx + 4]
        if len(group) >= 2 and _fragment_names_related(group):
            candidates.append({"strategy": "adjacent_related_fragments", "identifiers": group, "value": "".join(assignments[name] for name in group)})

    return _dedupe_candidates(candidates)


def decode_value(encoding: str, value: str) -> str:
    if encoding == "base64":
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
    if encoding == "hex":
        return bytes.fromhex(re.sub(r"\s+", "", value)).decode("utf-8", errors="replace")
    if encoding == "urlencoding":
        return unquote(value)
    raise ValueError("unsupported encoding")


def _extract_string_assignments(text: str) -> dict[str, str]:
    return build_symbol_table(text)


def _fragment_names_related(names: list[str]) -> bool:
    lowered = [name.lower() for name in names]
    if not any(any(marker in name for marker in ("part", "prefix", "body", "suffix", "token", "key", "secret")) for name in lowered):
        return False
    stems = [re.sub(r"(part|prefix|body|suffix|[0-9_])+", "", name) for name in lowered]
    return len(set(stems)) <= 2


def _dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for candidate in candidates:
        value = candidate["value"]
        if value in seen or len(value) < 8:
            continue
        seen.add(value)
        unique.append(candidate)
    return unique


def _looks_secret_by_context(value: str, context: str) -> bool:
    return len(value) >= 20 and SECRET_CONTEXT_RE.search(context + " " + value) is not None


def _clean_rel_path(value: object) -> str:
    path = str(value or ".").strip()
    path = path.replace("\\", "/").lstrip("/")
    return os.path.normpath(path).replace("\\", "/")


def _bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _redacted_limited(value: str, limit: int) -> str:
    redacted = redact_evidence(value)
    return redacted if len(redacted) <= limit else redacted[:limit] + "\n[truncated]"


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
