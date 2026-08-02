# Agentic Asset Discovery Demo Release

This directory is a partial release of the project for demonstration and
artifact-review purposes. It includes only a small subset of the code and one
synthetic Linux data instance to reduce misuse risk. After the paper is
published, the complete code and datasets will be shared on request with
verified researchers.

The released demo data is:

```text
data/linux/base_env_1/
```

## Released Methods

This release supports three extraction methods:

- `simple`: the **Pattern Match** baseline.
- `llm`: the **Single-pass LLM** baseline.
- `llm_agent`: the **agentic malware** method, implemented as bounded read-only agentic asset discovery.

All three embedding methods are included:

- `simple`
- `obfus_1`
- `obfus_2`

Only Qwen3.5-family models are supported in this release:

- `Qwen/Qwen3.5-2B`
- `Qwen/Qwen3.5-4B`
- `Qwen/Qwen3.5-9B`

## Quick Start

Run a small pattern-match extraction experiment:

```bash
python evaluate_extraction.py \
  --base-env ./data/linux/base_env_1 \
  --phase extract \
  --embedding-method simple \
  --extract-method simple \
  --runs 1
```

Run the single-pass LLM baseline:

```bash
python evaluate_extraction.py \
  --base-env ./data/linux/base_env_1 \
  --phase extract \
  --embedding-method obfus_1 \
  --extract-method llm \
  --model Qwen/Qwen3.5-4B \
  --runs 1
```

Run the agentic malware method:

```bash
python evaluate_extraction.py \
  --base-env ./data/linux/base_env_1 \
  --phase extract \
  --embedding-method obfus_1 \
  --extract-method llm_agent \
  --model Qwen/Qwen3.5-4B \
  --runs 1
```

The `exfiltrate` and `all` phases use a safe non-executable delivery-plan
validation stage. They do not execute upload commands or contact external
services.

## Direct Extraction

You can also run the extractor directly on the released demo environment:

```bash
python extract_assets.py \
  --root ./data/linux/base_env_1 \
  --output findings.json
```

For LLM-backed runs, provide both `--llm` and `--model`:

```bash
python extract_assets.py \
  --root ./data/linux/base_env_1 \
  --output findings.json \
  --llm llm_agent \
  --model Qwen/Qwen3.5-4B
```
