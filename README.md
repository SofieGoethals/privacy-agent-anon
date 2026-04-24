# Privacy Benchmark Artifact

Artifact for the paper *[Title redacted for review]*.

This repository contains the benchmark code, pre-computed results, and the analysis notebook needed to reproduce all figures and tables in the paper.

---

## Structure

```
├── src/
│   ├── scenarios.py                  # 100 negotiation scenarios + control variants
│   ├── privacy_benchmark_flexible.py # Baseline benchmark runner
│   ├── privacy_mitigation.py         # Mitigation policy runner (CATEGORY / GENERIC / NONE)
│   └── llm_judge.py                  # LLM-as-a-judge for privacy leakage detection
├── run_all.py                        # Runs the full benchmark suite in parallel
├── notebooks/
│   └── analysis.ipynb                # Reproduces all figures and tables from pre-computed results
├── results/                          # Pre-computed results (judged JSONL + CSV summaries)
└── Figures/                          # Generated figures and LaTeX tables
```

---

## Quickstart: reproduce figures from pre-computed results

This is the fastest path and does not require any API keys.

```bash
pip install -r requirements.txt
jupyter notebook notebooks/analysis.ipynb
```

Run all cells. The notebook reads from `results/` and writes figures to `Figures/`. All paper figures and tables are produced this way.

---

## Re-running the benchmark from scratch

Requires an [OpenRouter](https://openrouter.ai/) API key (models are accessed via the OpenRouter API). Running the full suite costs approximately $37 and takes ~40 hours of wall time.

**Setup:**

```bash
pip install -r requirements.txt
cp .env.example .env
# edit .env and add your OPENROUTER_API_KEY
```

**Full run:**

```bash
python run_all.py
```

Results are written to `privacy_benchmark_results/run_<timestamp>/`. After the run completes, update `RESULTS_DIR` in `notebooks/analysis.ipynb` to point at the new folder.

**Smoke test** (2 models × 2 scenarios × 1 rep, ~5 min, ~$0.10):

```bash
python run_all.py --test
```

---

## Models evaluated

All models are accessed via OpenRouter:

| Model | OpenRouter ID |
|---|---|
| Claude 3 Haiku | `anthropic/claude-3-haiku` |
| GPT-4.1-mini | `openai/gpt-4.1-mini` |
| Gemini 2.0 Flash | `google/gemini-2.0-flash-001` |
| Grok-3-mini | `x-ai/grok-3-mini-beta` |
| DeepSeek-Chat | `deepseek/deepseek-chat` |

---

## Pre-computed results

`results/` contains the output of the final benchmark run (April 2026):

- `summary_*.csv` — one row per run, keyword-detection fields
- `*_judged.jsonl` — same runs with LLM judge scores added (`llm_judge_leaked`, `llm_judge_severity`, `llm_judge_evidence`)

Files prefixed `runs_mitigation_` correspond to the three privacy policy conditions (CATEGORY, GENERIC, NONE); the others are baseline runs.

---

## Requirements

Python 3.10+. Install dependencies with:

```bash
pip install -r requirements.txt
```
