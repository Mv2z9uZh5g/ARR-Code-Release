from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DIMENSIONS = ("result_prefix", "phase", "embedding_method", "extract_method", "model", "runs")
TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})\.json$")
EXTRACT_METHOD_ORDER = {"simple": 0, "llm": 1, "llm_agent": 2}
LATEX_DIMENSION_LABELS = {
    "result_prefix": "Platform",
    "phase": "Phase",
    "embedding_method": "Embedding Method",
    "extract_method": "Extract Method",
    "model": "Model",
    "runs": "Runs",
}
LATEX_VALUE_LABELS = {
    "simple": "Simple",
    "llm": "LLM",
    "llm_agent": "LLM Agent",
    "extract": "Extract",
    "exfiltrate": "Deliver",
    "linux": "Linux",
    "maca": "macOS",
    "win64": "Windows",
}
LATEX_ASSET_LABELS = {
    "aws_access_key_pair": "AWS Key",
    "github_token": "GitHub Token",
    "kubeconfig_credential": "Kubernetes Credential",
    "openai_api_key": "OpenAI Key",
    "pii_bundle": "PII Bundle",
}


@dataclass(frozen=True)
class ResultRecord:
    path: Path
    result_prefix: str | None
    phase: str
    embedding_method: str
    extract_method: str
    model: str | None
    runs: int
    metrics: dict[str, Any]
    timing: dict[str, Any]
    timestamp: datetime

    @property
    def configuration_key(self) -> tuple[str, str, str, str, str, int]:
        return (
            canonical_model(self.result_prefix),
            canonical(self.phase),
            canonical(self.embedding_method),
            canonical(self.extract_method),
            canonical_model(self.model),
            self.runs,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Browse the latest extraction evaluation results.")
    parser.add_argument("--results-dir", default="./results", help="Directory containing evaluator JSON output. Default: ./results")
    parser.add_argument("--result-prefix", help="Filter by optional result prefix, such as linux, maca, or win64. Use 'none' for older/unprefixed results.")
    parser.add_argument("--phase", help="Filter by evaluation phase, such as extract, exfiltrate, or all.")
    parser.add_argument("--embedding-method", help="Filter by embedding method discovered in result metadata.")
    parser.add_argument("--extract-method", help="Filter by extraction method discovered in result metadata.")
    parser.add_argument("--model", help="Filter by model. Use 'none' for deterministic simple results.")
    parser.add_argument("--runs", type=int, help="Filter by run count.")
    parser.add_argument("--latex", action="store_true", help="Print a LaTeX table for a one-dimension comparison.")
    parser.add_argument("--finegrain", action="store_true", help="Show per-secret metrics instead of overall metrics.")
    parser.add_argument("--time", action="store_true", help="Show extraction timing columns/sections.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records, warnings = discover_results(Path(args.results_dir))
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not records:
        print(f"No readable result JSON files found under {Path(args.results_dir)}.", file=sys.stderr)
        return 1

    latest = latest_by_configuration(records)
    filters: dict[str, object | None] = {
        "result_prefix": args.result_prefix,
        "embedding_method": args.embedding_method,
        "phase": args.phase,
        "extract_method": args.extract_method,
        "model": args.model,
        "runs": args.runs,
    }
    missing = [dimension for dimension, value in filters.items() if value is None]
    if len(missing) > 1:
        print("Exactly one experiment dimension may be omitted.", file=sys.stderr)
        print("Missing dimensions:", file=sys.stderr)
        for dimension in missing:
            print(f"  - {dimension}", file=sys.stderr)
        return 2

    matched = filter_records(latest.values(), filters, comparison_dimension=missing[0] if missing else None)
    if not matched:
        print("No latest result matches the requested configuration.", file=sys.stderr)
        print_discovered_values(latest.values())
        return 1
    if not missing:
        if len(matched) != 1:
            print("More than one result matched all dimensions; check result metadata.", file=sys.stderr)
            return 1
        if args.latex:
            print("warning: --latex is ignored when printing a single detailed result.", file=sys.stderr)
        print_detail(matched[0], finegrain=args.finegrain, show_time=args.time)
        return 0

    print_comparison(missing[0], matched, latex=args.latex, filters=filters, finegrain=args.finegrain, show_time=args.time)
    return 0


def discover_results(results_dir: Path) -> tuple[list[ResultRecord], list[str]]:
    records: list[ResultRecord] = []
    warnings: list[str] = []
    if not results_dir.is_dir():
        return records, [f"results directory does not exist: {results_dir}"]
    for path in sorted(results_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = parse_record(path, data)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            warnings.append(f"skipping {path.name}: {exc}")
            continue
        records.append(record)
    return records, warnings


def parse_record(path: Path, data: dict[str, Any]) -> ResultRecord:
    config = data.get("config")
    metrics = data.get("metrics")
    timing = data.get("timing")
    if not isinstance(config, dict) or not isinstance(metrics, dict) or not isinstance(timing, dict):
        raise ValueError("missing config, metrics, or timing object")
    embedding_method = required_text(config, "embedding_method")
    prefix_value = config.get("result_prefix")
    result_prefix = str(prefix_value) if prefix_value else infer_legacy_result_prefix(path)
    phase = str(config.get("phase") or "extract")
    extract_method = normalize_extract_method(required_text(config, "extract_method"))
    runs_value = config.get("runs")
    if not isinstance(runs_value, int):
        raise ValueError("config.runs is not an integer")
    model_value = config.get("model") or config.get("loaded_model")
    model = str(model_value) if model_value else infer_legacy_model(path, embedding_method, extract_method, runs_value)
    timestamp = timestamp_from_path(path)
    return ResultRecord(path, result_prefix, phase, embedding_method, extract_method, model, runs_value, metrics, timing, timestamp)


def required_text(config: dict[str, Any], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"config.{name} is missing")
    return value


def normalize_extract_method(value: str) -> str:
    return value.split(":", 1)[0]


def infer_legacy_model(path: Path, embedding_method: str, extract_method: str, runs: int) -> str | None:
    prefix = f"eval_{canonical(embedding_method)}_{canonical(extract_method)}_"
    suffix_match = re.search(rf"_runs{runs}_\d{{8}}_\d{{6}}\.json$", path.name)
    if not path.name.startswith(prefix) or not suffix_match:
        return None
    model_token = path.name[len(prefix) : suffix_match.start()]
    return model_token or None


def infer_legacy_result_prefix(path: Path) -> str | None:
    # New prefixed filenames are shaped like eval_linux_extract_...
    # Older files have no result_prefix in config and should remain grouped as none.
    return None


def timestamp_from_path(path: Path) -> datetime:
    match = TIMESTAMP_RE.search(path.name)
    if match:
        return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
    return datetime.fromtimestamp(path.stat().st_mtime)


def canonical(value: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in value).strip("_")


def canonical_model(value: str | None) -> str:
    return canonical(value) if value else "none"


def latest_by_configuration(records: Iterable[ResultRecord]) -> dict[tuple[str, str, str, str, str, int], ResultRecord]:
    latest: dict[tuple[str, str, str, str, str, int], ResultRecord] = {}
    for record in records:
        previous = latest.get(record.configuration_key)
        if previous is None or record.timestamp > previous.timestamp:
            latest[record.configuration_key] = record
    return latest


def filter_records(
    records: Iterable[ResultRecord],
    filters: dict[str, object | None],
    comparison_dimension: str | None = None,
) -> list[ResultRecord]:
    matched: list[ResultRecord] = []
    for record in records:
        if filters.get("result_prefix") is not None and canonical_model_filter(str(filters["result_prefix"])) != canonical_model(record.result_prefix):
            continue
        if filters.get("phase") is not None and canonical(record.phase) != canonical(str(filters["phase"])):
            continue
        if filters["embedding_method"] is not None and canonical(record.embedding_method) != canonical(str(filters["embedding_method"])):
            continue
        if filters["extract_method"] is not None and canonical(record.extract_method) != canonical(str(filters["extract_method"])):
            continue
        if filters["model"] is not None:
            requested_model = canonical_model_filter(str(filters["model"]))
            if comparison_dimension == "extract_method" and canonical(record.extract_method) == "simple":
                if canonical_model(record.model) != "none":
                    continue
            elif canonical_model(record.model) != requested_model:
                continue
        if filters["runs"] is not None and record.runs != filters["runs"]:
            continue
        matched.append(record)
    return sorted(matched, key=lambda item: item.configuration_key)


def canonical_model_filter(value: str) -> str:
    return "none" if value.lower() in {"none", "null", "-"} else canonical(value)


def print_detail(record: ResultRecord, finegrain: bool = False, show_time: bool = False) -> None:
    print("Configuration")
    print("-------------")
    rows = [
        ("result_prefix", display_model(record.result_prefix)),
        ("phase", record.phase),
        ("embedding_method", record.embedding_method),
        ("extract_method", record.extract_method),
        ("model", display_model(record.model)),
        ("runs", str(record.runs)),
        ("result_file", record.path.name),
    ]
    print_key_values(rows)
    metrics = record.metrics
    print("\nMetrics")
    print("-------")
    if record.phase == "exfiltrate":
        print_key_values(
            [
                ("Successes", text_number(metrics.get("successes"))),
                ("Failures", text_number(metrics.get("failures"))),
                ("Accuracy", formatted_metric(metrics.get("accuracy"))),
            ]
        )
        return
    print_key_values(
        [
            ("TP", text_number(metrics.get("true_positives"))),
            ("FP", text_number(metrics.get("total_false_positives"))),
            ("FN", text_number(metrics.get("false_negatives"))),
            ("Precision", formatted_metric(metrics.get("precision"))),
            ("Recall", formatted_metric(metrics.get("recall"))),
            ("F1", formatted_metric(metrics.get("f1"))),
        ]
    )
    if show_time:
        timing = record.timing
        print("\nTiming")
        print("------")
        print_key_values(
            [
                ("Mean extraction time", seconds(timing.get("avg_extraction_seconds"))),
                ("LLM load time", seconds(timing.get("llm_load_seconds"))),
                ("Total runtime", seconds(timing.get("total_seconds"))),
            ]
        )
    if finegrain:
        asset_ids = per_asset_ids([record])
        if not asset_ids:
            print("\nPer-Secret Metrics")
            print("------------------")
            print("No per-secret metrics found in this result.")
            return
        print("\nPer-Secret Metrics")
        print("------------------")
        rows = [
            [
                asset_id,
                formatted_metric(per_asset_metric(record, asset_id, "precision")),
                formatted_metric(per_asset_metric(record, asset_id, "recall")),
                formatted_metric(per_asset_metric(record, asset_id, "f1")),
            ]
            for asset_id in asset_ids
        ]
        print_table(["secret", "Precision", "Recall", "F1"], rows)


def print_comparison(
    missing_dimension: str,
    records: list[ResultRecord],
    latex: bool = False,
    filters: dict[str, object | None] | None = None,
    finegrain: bool = False,
    show_time: bool = False,
) -> None:
    if finegrain:
        print_finegrain_comparison(missing_dimension, records, latex=latex, filters=filters, show_time=show_time)
        return
    headers = [missing_dimension]
    if missing_dimension == "extract_method":
        headers.append("model")
    exfiltrate_rows = all(record.phase == "exfiltrate" for record in records)
    headers.extend(["Accuracy"] if exfiltrate_rows else ["Precision", "Recall", "F1", "TP", "FP", "FN"])
    if show_time:
        headers.append("Mean extract (s)")
    rows: list[list[str]] = []
    for record in sorted(records, key=lambda item: dimension_sort_value(item, missing_dimension)):
        value = getattr(record, missing_dimension)
        row = [display_model(value) if missing_dimension == "model" else str(value)]
        if missing_dimension == "extract_method":
            row.append(display_model(record.model))
        if exfiltrate_rows:
            row.append(formatted_metric(record.metrics.get("accuracy")))
        else:
            row.extend(
                [
                    formatted_metric(record.metrics.get("precision")),
                    formatted_metric(record.metrics.get("recall")),
                    formatted_metric(record.metrics.get("f1")),
                    text_number(record.metrics.get("true_positives")),
                    text_number(record.metrics.get("total_false_positives")),
                    text_number(record.metrics.get("false_negatives")),
                ]
            )
        if show_time:
            row.append(formatted_seconds(record.timing.get("avg_extraction_seconds")))
        rows.append(row)
    if latex:
        latex_headers, latex_rows = latex_comparison_projection(missing_dimension, headers, rows)
        caption, label = latex_caption_and_label(missing_dimension, records, filters)
        print_latex_table(latex_headers, latex_rows, caption, label)
        return
    print(f"Comparison by {missing_dimension} (latest result per configuration)")
    print_table(headers, rows)


def print_finegrain_comparison(
    missing_dimension: str,
    records: list[ResultRecord],
    latex: bool = False,
    filters: dict[str, object | None] | None = None,
    show_time: bool = False,
) -> None:
    sorted_records = sorted(records, key=lambda item: dimension_sort_value(item, missing_dimension))
    asset_ids = per_asset_ids(sorted_records)
    if not asset_ids:
        print("No per-secret metrics found in the matched results.", file=sys.stderr)
        return
    row_headers = comparison_row_headers(missing_dimension)
    rows = [
        comparison_row_values(record, missing_dimension)
        + [
            formatted_metric(per_asset_metric(record, asset_id, metric_name))
            for asset_id in asset_ids
            for metric_name in ("precision", "recall", "f1")
        ]
        + ([formatted_seconds(record.timing.get("avg_extraction_seconds"))] if show_time else [])
        for record in sorted_records
    ]
    if latex:
        caption, label = latex_caption_and_label(missing_dimension, records, filters, finegrain=True)
        print_finegrain_latex_table(row_headers, asset_ids, rows, caption, label, show_time=show_time)
        return
    headers = row_headers + [f"{asset_id} {metric_name.title()}" for asset_id in asset_ids for metric_name in ("precision", "recall", "f1")]
    if show_time:
        headers.append("Mean extract (s)")
    print(f"Fine-grained comparison by {missing_dimension} (latest result per configuration)")
    print_table(headers, rows)


def comparison_row_headers(missing_dimension: str) -> list[str]:
    headers = [missing_dimension]
    if missing_dimension == "extract_method":
        return headers
    return headers


def comparison_row_values(record: ResultRecord, missing_dimension: str) -> list[str]:
    value = getattr(record, missing_dimension)
    return [display_model(value) if missing_dimension in {"model", "result_prefix"} else str(value)]


def per_asset_ids(records: Iterable[ResultRecord]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for record in records:
        per_asset = record.metrics.get("per_asset")
        if not isinstance(per_asset, dict):
            continue
        for asset_id in per_asset:
            if isinstance(asset_id, str) and asset_id not in seen:
                seen.add(asset_id)
                ids.append(asset_id)
    return ids


def per_asset_metric(record: ResultRecord, asset_id: str, metric_name: str) -> Any:
    per_asset = record.metrics.get("per_asset")
    if not isinstance(per_asset, dict):
        return None
    metric = per_asset.get(asset_id)
    if not isinstance(metric, dict):
        return None
    return metric.get(metric_name)


def dimension_sort_value(record: ResultRecord, dimension: str) -> str:
    if dimension == "extract_method":
        return f"{EXTRACT_METHOD_ORDER.get(canonical(record.extract_method), 99):02d}:{record.extract_method}"
    value = getattr(record, dimension)
    return canonical_model(value) if dimension in {"model", "result_prefix"} else str(value)


def print_discovered_values(records: Iterable[ResultRecord]) -> None:
    records = list(records)
    print("Discovered values:", file=sys.stderr)
    for dimension in DIMENSIONS:
        values = {
            display_model(getattr(record, dimension)) if dimension in {"model", "result_prefix"} else str(getattr(record, dimension))
            for record in records
        }
        print(f"  {dimension}: {', '.join(sorted(values))}", file=sys.stderr)


def display_model(model: str | None) -> str:
    return model or "none"


def text_number(value: Any) -> str:
    return "-" if value is None else str(value)


def formatted_metric(value: Any) -> str:
    return "-" if not isinstance(value, (int, float)) else f"{float(value):.3f}"


def formatted_seconds(value: Any) -> str:
    return "-" if not isinstance(value, (int, float)) else f"{float(value):.3f}"


def seconds(value: Any) -> str:
    return "-" if not isinstance(value, (int, float)) else f"{float(value):.3f} s"


def print_key_values(rows: list[tuple[str, str]]) -> None:
    width = max(len(name) for name, _value in rows)
    for name, value in rows:
        print(f"{name:<{width}} : {value}")


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold")
        for header in headers:
            table.add_column(header, no_wrap=True)
        for row in rows:
            table.add_row(*row)
        console = Console()
        Console(width=max(console.width, 120)).print(table)
        return
    except ImportError:
        pass
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    print(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def print_latex_table(headers: list[str], rows: list[list[str]], caption: str, label: str) -> None:
    """Print a paper-ready LaTeX table without assuming particular dimensions."""
    columns = "|" + "|".join("c" for _header in headers) + "|"
    print(r"\begin{table*}[!t]\renewcommand{\arraystretch}{1.0}")
    print(r"  \centering")
    print(r"  \fontsize{7}{10}\selectfont")
    print(rf"  \caption{{{latex_escape(caption)}}}")
    print(rf"\begin{{tabular}}{{{columns}}}")
    print(r"\hline")
    print(" & ".join(rf"\textbf{{{latex_escape(header)}}}" for header in headers) + r" \\ \hline\hline")
    print()
    for row in rows:
        print(" & ".join(latex_escape(value) for value in row) + r" \\ \hline")
    print()
    print(r"\end{tabular}")
    print(rf"  \label{{{label}}}")
    print(r"\end{table*}")


def print_finegrain_latex_table(
    row_headers: list[str],
    asset_ids: list[str],
    rows: list[list[str]],
    caption: str,
    label: str,
    show_time: bool = False,
) -> None:
    """Print grouped per-secret precision/recall/F1 columns."""
    total_columns = len(row_headers) + 3 * len(asset_ids) + int(show_time)
    columns = "|" + "|".join("c" for _index in range(total_columns)) + "|"
    print(r"\begin{table*}[!t]\renewcommand{\arraystretch}{1.0}")
    print(r"  \centering")
    print(r"  \fontsize{7}{10}\selectfont")
    print(rf"  \caption{{{latex_escape(caption)}}}")
    print()
    print(rf"\begin{{tabular}}{{{columns}}}")
    print(r"\hline")
    latex_row_headers = [latex_dimension_label(header) for header in row_headers]
    latex_asset_ids = [latex_asset_label(asset_id) for asset_id in asset_ids]
    latex_rows = [
        [
            latex_value_label(row_headers[index], value) if index < len(row_headers) else value
            for index, value in enumerate(row)
        ]
        for row in rows
    ]
    header_cells = [rf"\multirow{{2}}{{*}}{{{latex_escape(header)}}}" for header in latex_row_headers]
    header_cells.extend(rf"\multicolumn{{3}}{{c|}}{{{latex_escape(asset_id)}}}" for asset_id in latex_asset_ids)
    if show_time:
        header_cells.append(r"\multirow{2}{*}{Extraction time (s)}")
    print(" & ".join(header_cells) + r" \\  " + rf"\cline{{{len(row_headers) + 1}-{len(row_headers) + 3 * len(asset_ids)}}}")
    print()
    metric_cells = [""] * len(row_headers)
    for _asset_id in asset_ids:
        metric_cells.extend(["Precision", "Recall", "F1"])
    if show_time:
        metric_cells.append("")
    print(" & ".join(metric_cells) + r" \\  \hline\hline")
    print()
    for row in latex_rows:
        print(" & ".join(latex_escape(value) for value in row) + r"  \\ \hline")
    print()
    print(r"\end{tabular}")
    print(rf"  \label{{{label}}}")
    print(r"\end{table*}")


def latex_comparison_projection(
    missing_dimension: str,
    headers: list[str],
    rows: list[list[str]],
) -> tuple[list[str], list[list[str]]]:
    omitted = {"TP", "FP", "FN"}
    if missing_dimension == "extract_method":
        omitted.add("model")
    selected_indices = [index for index, header in enumerate(headers) if header not in omitted]
    latex_headers = [
        "Extraction time (s)" if headers[index] == "Mean extract (s)" else latex_dimension_label(headers[index])
        for index in selected_indices
    ]
    latex_rows = [
        [latex_value_label(headers[index], row[index]) for index in selected_indices]
        for row in rows
    ]
    return latex_headers, latex_rows


def latex_caption_and_label(
    missing_dimension: str,
    records: list[ResultRecord],
    filters: dict[str, object | None] | None,
    finegrain: bool = False,
) -> tuple[str, str]:
    context = fixed_comparison_context(missing_dimension, records, filters)
    compared_name = latex_dimension_label(missing_dimension)
    caption = f"{'Fine-grained per-secret e' if finegrain else 'E'}xtraction results comparing {compared_name}"
    if context:
        qualifiers = [f"{latex_dimension_label(name)} {latex_value_label(name, value)}" for name, value in context]
        caption += " for " + ", ".join(qualifiers[:-1])
        if len(qualifiers) > 1:
            caption += f", and {qualifiers[-1]}"
        else:
            caption += qualifiers[-1]
    caption += "."
    label_parts = ["tab", "extraction_results"]
    if finegrain:
        label_parts.append("finegrain")
    label_parts.extend(["compare", canonical(missing_dimension).lower()])
    for name, value in context:
        label_parts.extend([canonical(name).lower(), canonical(value).lower()])
    return caption, ":".join(label_parts[:2]) + "_" + "_".join(label_parts[2:])


def fixed_comparison_context(
    missing_dimension: str,
    records: list[ResultRecord],
    filters: dict[str, object | None] | None,
) -> list[tuple[str, str]]:
    context: list[tuple[str, str]] = []
    for dimension in DIMENSIONS:
        if dimension == missing_dimension:
            continue
        requested = filters.get(dimension) if filters else None
        if requested is not None:
            context.append((dimension, str(requested)))
            continue
        values = {display_dimension(record, dimension) for record in records}
        if dimension == "result_prefix" and values == {"none"}:
            continue
        if dimension == "phase" and values == {"extract"}:
            continue
        if len(values) == 1:
            context.append((dimension, values.pop()))
    return context


def display_dimension(record: ResultRecord, dimension: str) -> str:
    value = getattr(record, dimension)
    return display_model(value) if dimension in {"model", "result_prefix"} else str(value)


def humanize_dimension(dimension: str) -> str:
    return dimension.replace("_", " ")


def latex_dimension_label(dimension: str) -> str:
    return LATEX_DIMENSION_LABELS.get(dimension, humanize_dimension(dimension).title())


def latex_value_label(dimension: str, value: str) -> str:
    if dimension == "model":
        return value
    normalized = canonical(value).lower()
    if normalized in LATEX_VALUE_LABELS:
        return LATEX_VALUE_LABELS[normalized]
    if dimension in {"extract_method", "phase", "result_prefix"}:
        return humanize_dimension(value).title()
    return value


def latex_asset_label(asset_id: str) -> str:
    return LATEX_ASSET_LABELS.get(asset_id, humanize_dimension(asset_id).title())


def latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(character, character) for character in str(value))


if __name__ == "__main__":
    raise SystemExit(main())
