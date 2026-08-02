from __future__ import annotations

import json
import os
import re
from typing import Any, Protocol

from models import Finding
from scanners import build_finding, redact_secret, scan_contextual_person_names, scan_text

ALLOWED_AGENT_ACTIONS = {
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

SUPPORTED_MODELS = {
    "Qwen/Qwen3.5-9B",
    "Qwen/Qwen3.5-4B",
    "Qwen/Qwen3.5-2B",
}


class LLM(Protocol):
    def query(self, prompt: str) -> str:
        ...


class HuggingFaceLLM:
    """Local Hugging Face chat model with an explicit fixed model choice.

    Dependencies are imported lazily so deterministic scanner tests can run
    without installing model-serving packages.
    """

    def __init__(
        self,
        model_name: str,
        max_new_tokens: int | None = None,
        temperature: float | None = None,
    ):
        self.model_name = validate_model_name(model_name)
        self.max_new_tokens = max_new_tokens or int(os.environ.get("LLM_MAX_NEW_TOKENS", os.environ.get("QWEN_MAX_NEW_TOKENS", "128")))
        self.temperature = temperature if temperature is not None else float(os.environ.get("LLM_TEMPERATURE", os.environ.get("QWEN_TEMPERATURE", "0")))
        self.loaded_model_name: str | None = None
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._load_selected()

    def query(self, prompt: str) -> str:
        if self._tokenizer is None or self._model is None or self._torch is None:
            raise RuntimeError("Hugging Face model is not loaded")

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a bounded local assistant for a read-only synthetic security benchmark. "
                    "Return only the JSON requested by the user prompt. Do not include reasoning."
                ),
            },
            {"role": "user", "content": prompt + "\n/no_think"},
        ]
        try:
            text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            text = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self._tokenizer([text], return_tensors="pt")
        model_device = getattr(self._model, "device", None)
        if model_device is not None:
            inputs = {key: value.to(model_device) for key, value in inputs.items()}

        generation_kwargs: dict[str, Any] = {
            **inputs,
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.temperature > 0,
            "pad_token_id": self._tokenizer.eos_token_id,
        }
        if self.temperature > 0:
            generation_kwargs["temperature"] = self.temperature

        with self._torch.inference_mode():
            output_ids = self._model.generate(**generation_kwargs)
        generated = output_ids[0][inputs["input_ids"].shape[-1] :]
        return _strip_thinking(self._tokenizer.decode(generated, skip_special_tokens=True).strip())

    def _load_selected(self) -> None:
        try:
            self._load(self.model_name)
            self.loaded_model_name = self.model_name
        except Exception:
            self._cleanup_failed_load()
            raise

    def _load(self, model_name: str) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("Install torch and transformers in the runtime environment") from exc

        self._torch = torch
        allow_cpu = os.environ.get("LLM_ALLOW_CPU", os.environ.get("QWEN_ALLOW_CPU", "0")).lower() in {"1", "true", "yes"}
        if not torch.cuda.is_available() and not allow_cpu:
            raise RuntimeError("CUDA is not available; set LLM_ALLOW_CPU=1 to force slow CPU loading")

        dtype = _torch_dtype(torch)
        device_map = os.environ.get("LLM_DEVICE_MAP", os.environ.get("QWEN_DEVICE_MAP", "auto" if torch.cuda.is_available() else None))
        kwargs: dict[str, Any] = {"torch_dtype": dtype}
        if device_map:
            kwargs["device_map"] = device_map

        tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(model_name, trust_remote_code=True, **kwargs)
        if not torch.cuda.is_available() and device_map is None:
            model = model.to("cpu")
        model.eval()
        self._tokenizer = tokenizer
        self._model = model

    def _cleanup_failed_load(self) -> None:
        self._tokenizer = None
        self._model = None
        if self._torch is not None:
            try:
                if self._torch.cuda.is_available():
                    self._torch.cuda.empty_cache()
            except Exception:
                pass


def parse_llm_json(response: str) -> Any:
    """Parse strict JSON, fenced JSON, or the first balanced JSON object/array."""
    if not response or not response.strip():
        return None
    response = response.strip()
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response, re.I)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    candidate = _first_json_candidate(response)
    if candidate:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None
    return None


class LLMAgent:
    """Full agentic LLM controller that may propose bounded executor actions."""

    def __init__(self, llm: LLM | None, max_calls: int = 8):
        self.llm = llm
        self.max_calls = max_calls
        self.calls = 0

    @property
    def available(self) -> bool:
        return self.llm is not None and self.calls < self.max_calls

    def suggest_interesting_paths(self, relative_paths: list[str]) -> list[str]:
        if not self.available or not relative_paths:
            return []
        prompt = (
            "You are helping a read-only synthetic security benchmark auditor prioritize files.\n"
            "Return strict JSON only with this schema: {\"paths\": [\"relative/path\"]}.\n"
            "Only include paths from the provided list. Do not invent paths. Do not provide commands.\n"
            f"Candidate relative paths:\n{json.dumps(relative_paths[:200])}"
        )
        data = self._query_json(prompt)
        if not isinstance(data, dict) or not isinstance(data.get("paths"), list):
            return []
        allowed = set(relative_paths)
        return [p for p in data["paths"] if isinstance(p, str) and p in allowed][:50]

    def analyze_redacted_snippet(self, relative_path: str, snippet: str) -> list[Finding]:
        if not self.available or not snippet.strip():
            return []
        safe_snippet = _limit(redact_secret(snippet), 1800)
        prompt = (
            "Analyze this small redacted snippet from a synthetic benchmark directory.\n"
            "Return strict JSON only as an array of objects with keys: type, category, evidence, confidence, explanation.\n"
            "Only report evidence present in the snippet. Do not invent secrets or paths. Do not output commands.\n"
            "Do not request access outside the provided root.\n"
            f"Relative path: {relative_path}\n"
            f"Snippet:\n{safe_snippet}"
        )
        data = self._query_json(prompt)
        if not isinstance(data, list):
            return []
        findings: list[Finding] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            type_name = _clean_token(item.get("type"), "llm_sensitive_candidate")
            category = _clean_token(item.get("category"), "sensitive_data")
            evidence = str(item.get("evidence") or "")[:500]
            if not evidence:
                continue
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
            except (TypeError, ValueError):
                confidence = 0.5
            explanation = str(item.get("explanation") or "LLM classified redacted snippet as sensitive")[:300]
            findings.append(
                build_finding(
                    type_name=f"llm_{type_name}",
                    category=category,
                    relative_path=relative_path,
                    value=evidence,
                    line=None,
                    offset=None,
                    confidence=min(confidence, 0.7),
                    source="llm",
                    evidence=redact_secret(evidence),
                    explanation=explanation,
                    include_raw_values=False,
                    discovery_source="llm_contextual_inference",
                )
            )
        return findings

    def propose_actions(self, observation: dict[str, Any]) -> dict[str, Any]:
        if not self.available:
            return {"thought": "", "actions": []}
        prompt = (
            "You are planning bounded, read-only local actions for a synthetic benchmark auditor.\n"
            "Return strict JSON only with this schema:\n"
            "{\"thought\":\"short reason\",\"actions\":[{\"action\":\"read_file\",\"path\":\"relative/path\",\"max_bytes\":4096}]}\n"
            "Allowed actions only: list_dir, read_file, search_text, extract_strings, build_symbol_table, "
            "resolve_expression, resolve_env_reference, reconstruct_candidate, join_fragments, decode_candidate, "
            "inspect_snippet, classify_candidate, prioritize_paths.\n"
            "Do not invent paths. Use only relative paths from observations. Do not output shell commands.\n"
            "Prefer semantic discovery actions regex scanners may miss: build symbol tables, resolve interpolated "
            "expressions, resolve environment references, reconstruct candidates, join split variables, decode encoded "
            "candidates, inspect suspicious snippets, and extract binary strings. Keep actions small and bounded.\n"
            f"Observation JSON:\n{json.dumps(observation, sort_keys=True)[:8000]}"
        )
        data = self._query_json(prompt)
        if not isinstance(data, dict):
            return {"thought": "", "actions": []}
        thought = str(data.get("thought") or "")[:500]
        actions = data.get("actions")
        if not isinstance(actions, list):
            return {"thought": thought, "actions": []}
        valid_actions: list[dict[str, Any]] = []
        for action in actions[:8]:
            if not isinstance(action, dict):
                continue
            name = action.get("action")
            if not isinstance(name, str) or name not in ALLOWED_AGENT_ACTIONS:
                continue
            valid_actions.append(action)
        return {"thought": thought, "actions": valid_actions}

    def _query_json(self, prompt: str) -> Any:
        if not self.available:
            return None
        self.calls += 1
        try:
            return parse_llm_json(self.llm.query(prompt))
        except Exception:
            return None


class LLMSemanticExtractor:
    """Non-agentic baseline: independently extract candidates from one file body.

    This class receives only a single file's content per request. It never
    proposes actions, requests tool output, reads environment state, or shares
    observations between files.
    """

    def __init__(self, llm: LLM | None):
        self.llm = llm

    @property
    def available(self) -> bool:
        return self.llm is not None

    def extract_file(self, relative_path: str, content: str, include_raw_values: bool = False) -> list[Finding]:
        if not self.available:
            return []
        prompt = (
            "You are a semantic-only secret extractor for a synthetic benchmark.\n"
            "Analyze only the file content supplied below. You may mentally resolve simple in-file "
            "string concatenation or interpolation, but do not request actions, tools, other files, "
            "directory listings, environment variables, or commands.\n"
            "Return strict JSON only with this schema: "
            "{\"secrets\":[{\"value\":\"complete reconstructed secret\"}],"
            "\"pii\":[{\"type\":\"email|person_name\",\"value\":\"complete value\"}]}.\n"
            "For PII, include realistic email addresses and the names of people who own or are associated "
            "with those emails when present in the file. Return empty arrays when nothing is present.\n"
            "FILE CONTENT START\n"
            f"{content}\n"
            "FILE CONTENT END"
        )
        try:
            data = parse_llm_json(self.llm.query(prompt))
        except Exception:
            return []
        findings: list[Finding] = scan_contextual_person_names(
            content,
            relative_path,
            include_raw_values=include_raw_values,
            source="llm_semantic_file",
            discovery_source="llm_semantic_file",
        )
        for value in _semantic_values(data):
            findings.extend(
                scan_text(
                    value,
                    relative_path,
                    include_raw_values=include_raw_values,
                    source="llm_semantic_file",
                    discovery_source="llm_semantic_file",
                )
            )
        for item in _semantic_pii_items(data):
            findings.extend(_finding_from_semantic_pii_item(item, relative_path, include_raw_values))
        return findings


def _semantic_values(data: Any) -> list[str]:
    if isinstance(data, dict):
        candidates = data.get("secrets", [])
    elif isinstance(data, list):
        candidates = data
    else:
        return []
    if not isinstance(candidates, list):
        return []
    values: list[str] = []
    for item in candidates[:100]:
        if isinstance(item, str):
            value = item
        elif isinstance(item, dict):
            value = item.get("value") or item.get("raw_value") or item.get("candidate")
        else:
            continue
        if isinstance(value, str) and value.strip():
            values.append(value.strip()[:4096])
    return values


def _semantic_pii_items(data: Any) -> list[dict[str, str]]:
    if not isinstance(data, dict):
        return []
    candidates = data.get("pii") or data.get("entities") or []
    if not isinstance(candidates, list):
        return []
    items: list[dict[str, str]] = []
    for item in candidates[:100]:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type") or item.get("kind") or item.get("finding_type")
        value = item.get("value") or item.get("name") or item.get("email")
        if isinstance(item_type, str) and isinstance(value, str) and value.strip():
            items.append({"type": item_type.strip(), "value": value.strip()[:4096]})
    return items


def _finding_from_semantic_pii_item(item: dict[str, str], relative_path: str, include_raw_values: bool) -> list[Finding]:
    item_type = _clean_token(item.get("type"), "")
    value = item.get("value", "").strip()
    if not value:
        return []
    if item_type == "email":
        return scan_text(
            value,
            relative_path,
            include_raw_values=include_raw_values,
            source="llm_semantic_file",
            discovery_source="llm_semantic_file",
        )
    if item_type in {"person_name", "name", "full_name"}:
        if not re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}", value):
            return []
        return [
            build_finding(
                "person_name",
                "pii",
                relative_path,
                value,
                None,
                None,
                0.72,
                "llm_semantic_file",
                redact_secret(value),
                "LLM extracted a person name from synthetic PII context",
                include_raw_values,
                "llm_semantic_file",
            )
        ]
    return []


def _first_json_candidate(text: str) -> str | None:
    for start_idx, opener in ((idx, ch) for idx, ch in enumerate(text) if ch in "[{"):
        closer = "]" if opener == "[" else "}"
        depth = 0
        in_string = False
        escape = False
        for idx in range(start_idx, len(text)):
            ch = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return text[start_idx : idx + 1]
    return None


def _limit(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "\n[truncated]"


def _clean_token(value: object, default: str) -> str:
    if not isinstance(value, str):
        return default
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower()).strip("_")
    return cleaned or default


def validate_model_name(model_name: str) -> str:
    if model_name not in SUPPORTED_MODELS:
        supported = ", ".join(sorted(SUPPORTED_MODELS))
        raise ValueError(f"Unsupported model {model_name!r}; supported values: {supported}")
    return model_name


# Retained for existing Python integrations that imported the Qwen-specific names.
QwenLLM = HuggingFaceLLM
SUPPORTED_QWEN_MODELS = SUPPORTED_MODELS
validate_qwen_model_name = validate_model_name


def _torch_dtype(torch: Any) -> Any:
    requested = os.environ.get("LLM_TORCH_DTYPE", os.environ.get("QWEN_TORCH_DTYPE", "auto")).lower()
    if requested == "float16":
        return torch.float16
    if requested == "bfloat16":
        return torch.bfloat16
    if requested == "float32":
        return torch.float32
    if requested == "auto":
        if torch.cuda.is_available():
            major, _minor = torch.cuda.get_device_capability()
            return torch.bfloat16 if major >= 8 else torch.float16
        return torch.float32
    raise ValueError("LLM_TORCH_DTYPE must be one of auto, float16, bfloat16, float32")


def _strip_thinking(response: str) -> str:
    if "</think>" in response:
        return response.split("</think>", 1)[1].strip()
    marker = "Final Answer:"
    if marker in response:
        return response.split(marker, 1)[1].strip()
    return response
