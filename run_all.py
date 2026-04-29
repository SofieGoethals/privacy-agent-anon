"""
run_all.py

Runs the full benchmark suite in parallel — one subprocess per model — then
runs the LLM judge on all results.

Usage:
    python run_all.py            # full run (~$37, ~40h wall time)
    python run_all.py --test     # smoke test: 2 models × 2 scenarios × 1 rep × both strategies

The --test flag is useful to verify the pipeline end-to-end before committing
to a full run. It writes to privacy_benchmark_results/test_<timestamp>/ so it
doesn't interfere with real results.

Each model runs in its own subprocess, executing both:
  1. privacy_benchmark_flexible.py  (baseline / FULL policy)
  2. privacy_mitigation.py          (2 mitigation policies: CATEGORY, GENERIC)

After all subprocesses finish, the LLM judge is run on all result files.
"""

import argparse
import asyncio
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------

CHAT_MODEL_INFO = {
    "vision": False,
    "function_calling": True,
    "json_output": True,
    "family": "unknown",
}

MODELS = [
    {
        "model": "anthropic/claude-3-haiku",
        "base_url": "https://openrouter.ai/api/v1",
    },
    # claude-3.5-haiku commented out: high output price ($4/M tokens)
    # {
    #     "model": "anthropic/claude-3.5-haiku",
    #     "base_url": "https://openrouter.ai/api/v1",
    # },
    {
        "model": "openai/gpt-4.1-mini",
        "base_url": "https://openrouter.ai/api/v1",
    },
    {
        "model": "x-ai/grok-3-mini-beta",
        "base_url": "https://openrouter.ai/api/v1",
    },
    {
        "model": "deepseek/deepseek-chat",
        "base_url": "https://openrouter.ai/api/v1",
    },
    {
        "model": "google/gemini-2.0-flash-001",
        "base_url": "https://openrouter.ai/api/v1",
    },
    # meta-llama/llama-3.3-70b-instruct commented out: second most expensive model
    # {
    #     "model": "meta-llama/llama-3.3-70b-instruct",
    #     "base_url": "https://openrouter.ai/api/v1",
    # },
]

# ---------------------------------------------------------------------------
# Per-model worker script (written to a temp file and executed as subprocess)
# ---------------------------------------------------------------------------

WORKER_TEMPLATE = '''
import asyncio, os, sys
sys.path.insert(0, {src_dir!r})

from dotenv import load_dotenv
load_dotenv(os.path.join({root_dir!r}, ".env"))

from scenarios import create_100_scenarios, create_control_scenario
from privacy_benchmark_flexible import run_benchmark
from privacy_mitigation import run_mitigation_benchmark, policy_category, policy_generic

CHAT_MODEL_INFO = {chat_model_info!r}
API_KEY = os.environ.get("OPENROUTER_API_KEY")

model_cfg = {{
    "model": {model!r},
    "base_url": {base_url!r},
    "api_key": API_KEY,
    "model_info": CHAT_MODEL_INFO,
}}

scenarios = create_100_scenarios()
out_dir = {out_dir!r}
repetitions = {repetitions!r}
max_messages = {max_messages!r}
model_slug = {model_slug!r}

# Use model-slug-based filenames so parallel workers never collide.
# Passing as resume_from means: use this path as output (and resume if it already exists).
baseline_jsonl = os.path.join(out_dir, f"runs_{{model_slug}}.jsonl")
mitigation_jsonl = os.path.join(out_dir, f"runs_mitigation_{{model_slug}}.jsonl")

print(f"[{{model_cfg['model']}}] Starting baseline benchmark...")
asyncio.run(run_benchmark(
    models=[model_cfg],
    scenarios=scenarios,
    repetitions=repetitions,
    attacker_strategies={baseline_strategies!r},
    include_control=True,
    out_dir=out_dir,
    max_messages=max_messages,
    resume_from=baseline_jsonl,
))

print(f"[{{model_cfg['model']}}] Starting mitigation benchmark...")
asyncio.run(run_mitigation_benchmark(
    models=[model_cfg],
    scenarios=scenarios,
    policies=[policy_category(), policy_generic()],
    repetitions=repetitions,
    attacker_strategies={mitigation_strategies!r},
    out_dir=out_dir,
    max_messages=max_messages,
    resume_from=mitigation_jsonl,
))

print(f"[{{model_cfg['model']}}] Done.")
'''

# ---------------------------------------------------------------------------
# Judge runner
# ---------------------------------------------------------------------------

JUDGE_TEMPLATE = '''
import asyncio, glob, os, sys
sys.path.insert(0, {src_dir!r})

from dotenv import load_dotenv
load_dotenv(os.path.join({root_dir!r}, ".env"))

from llm_judge import judge_results_file_async
from scenarios import create_100_scenarios

all_scenarios = create_100_scenarios()
scenario_lookup = {{s.scenario_id: s for s in all_scenarios}}
for s in all_scenarios:
    ctrl = s.scenario_id + "_control"
    scenario_lookup[ctrl] = s

out_dir = {out_dir!r}

# Find all unjudged JSONL files in out_dir
all_jsonl = sorted(
    f for f in glob.glob(os.path.join(out_dir, "runs_*.jsonl"))
    if "_judged" not in f
)
print(f"Found {{len(all_jsonl)}} result file(s) to judge.")

for jsonl_path in all_jsonl:
    out_path = jsonl_path.replace(".jsonl", "_judged.jsonl")
    checkpoint = jsonl_path + ".judge_checkpoint.json"
    print(f"\\nJudging: {{jsonl_path}}")
    asyncio.run(judge_results_file_async(
        jsonl_path,
        out_jsonl=out_path,
        scenario_lookup=scenario_lookup,
        checkpoint_path=checkpoint,
        save_every=20,
        verbose=True,
    ))
'''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def model_slug(model_name: str) -> str:
    return model_name.replace("/", "_").replace("-", "_").replace(".", "_")


def write_worker(path: Path, model: dict, out_dir: str, repetitions: int,
                 max_messages: int, baseline_strategies: list, mitigation_strategies: list,
                 src_dir: str, root_dir: str) -> None:
    script = WORKER_TEMPLATE.format(
        src_dir=src_dir,
        root_dir=root_dir,
        chat_model_info=CHAT_MODEL_INFO,
        model=model["model"],
        base_url=model["base_url"],
        out_dir=out_dir,
        repetitions=repetitions,
        max_messages=max_messages,
        baseline_strategies=baseline_strategies,
        mitigation_strategies=mitigation_strategies,
        model_slug=model_slug(model["model"]),
    )
    path.write_text(script)


def write_judge(path: Path, out_dir: str, src_dir: str, root_dir: str) -> None:
    script = JUDGE_TEMPLATE.format(
        src_dir=src_dir,
        root_dir=root_dir,
        out_dir=out_dir,
    )
    path.write_text(script)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run full benchmark suite in parallel.")
    parser.add_argument(
        "--test", action="store_true",
        help="Smoke-test mode: 2 scenarios, 1 rep, default strategy only. "
             "Writes to privacy_benchmark_results/test_<timestamp>/.",
    )
    parser.add_argument(
        "--resume", metavar="FOLDER",
        help="Resume a previous run from the given results folder. "
             "Reuses existing JSONL files and skips completed runs.",
    )
    args = parser.parse_args()

    root_dir = str(Path(__file__).parent.resolve())
    src_dir = str(Path(__file__).parent / "src")

    if args.test:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = str(Path(root_dir) / "privacy_benchmark_results" / f"test_{timestamp}")
        repetitions = 1
        max_messages = 6     # shorter conversations to save time/cost
        baseline_strategies = ["default", "aggressive"]
        mitigation_strategies = ["default", "aggressive"]
        models = MODELS[:2]  # gpt-4.1-mini + deepseek (first 2 non-haiku models)
        print("=== TEST MODE: 2 models × 2 scenarios × 1 rep ===")
        print(f"Output dir: {out_dir}")
    elif args.resume:
        out_dir = str(Path(args.resume).resolve())
        if not Path(out_dir).exists():
            print(f"ERROR: Resume folder not found: {out_dir}")
            sys.exit(1)
        repetitions = 3
        max_messages = 14
        baseline_strategies = ["default", "aggressive"]
        mitigation_strategies = ["default", "aggressive"]
        models = MODELS
        print(f"=== RESUME RUN: {len(models)} models in parallel ===")
        print(f"Resuming from: {out_dir}")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = str(Path(root_dir) / "privacy_benchmark_results" / f"run_{timestamp}")
        repetitions = 3       # reduced from 5 for cost savings
        max_messages = 14
        baseline_strategies = ["default", "aggressive"]
        mitigation_strategies = ["default", "aggressive"]
        models = MODELS
        print(f"=== FULL RUN: {len(models)} models in parallel ===")
        print(f"Output dir: {out_dir}")

    os.makedirs(out_dir, exist_ok=True)

    # Write per-model worker scripts to a temp dir
    tmp_dir = Path(root_dir) / ".run_workers"
    tmp_dir.mkdir(exist_ok=True)

    # In test mode, limit to 2 scenarios by monkey-patching create_100_scenarios
    # We do this by injecting a wrapper in the worker script
    worker_paths = []
    for model in models:
        slug = model_slug(model["model"])
        path = tmp_dir / f"worker_{slug}.py"

        if args.test:
            # Inject scenario limit into the worker
            script = WORKER_TEMPLATE.format(
                src_dir=src_dir,
                root_dir=root_dir,
                chat_model_info=CHAT_MODEL_INFO,
                model=model["model"],
                base_url=model["base_url"],
                out_dir=out_dir,
                repetitions=repetitions,
                max_messages=max_messages,
                baseline_strategies=baseline_strategies,
                mitigation_strategies=mitigation_strategies,
                model_slug=slug,
            )
            # Limit to 2 scenarios
            script = script.replace(
                "scenarios = create_100_scenarios()",
                "scenarios = create_100_scenarios()[:2]  # TEST MODE: 2 scenarios only"
            )
            path.write_text(script)
        else:
            write_worker(
                path, model, out_dir, repetitions, max_messages,
                baseline_strategies, mitigation_strategies, src_dir, root_dir,
            )
        worker_paths.append((model["model"], path))

    judge_path = tmp_dir / "judge_all.py"
    write_judge(judge_path, out_dir, src_dir, root_dir)

    # Launch all workers in parallel
    print(f"\nLaunching {len(worker_paths)} parallel worker(s)...\n")
    start = time.time()

    procs = []
    log_paths = []
    for model_name, script_path in worker_paths:
        log_path = tmp_dir / f"log_{model_slug(model_name)}.txt"
        log_paths.append((model_name, log_path))
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=root_dir,
        )
        procs.append((model_name, proc, log_file))
        print(f"  Started: {model_name}  (log: {log_path.name})")

    print("\nWaiting for all workers to finish...")
    failed = []
    for model_name, proc, log_file in procs:
        ret = proc.wait()
        log_file.close()
        status = "OK" if ret == 0 else f"FAILED (exit {ret})"
        print(f"  {model_name}: {status}")
        if ret != 0:
            failed.append(model_name)

    elapsed = time.time() - start
    print(f"\nAll workers done in {elapsed/3600:.1f}h ({elapsed/60:.0f} min).")

    if failed:
        print(f"\nWARNING: {len(failed)} worker(s) failed: {failed}")
        print("Check logs in .run_workers/ for details.")
        print("Running LLM judge on results from successful workers...")
    else:
        print("\nAll workers succeeded. Running LLM judge...")

    judge_proc = subprocess.run(
        [sys.executable, str(judge_path)],
        cwd=root_dir,
    )
    if judge_proc.returncode != 0:
        print("WARNING: LLM judge exited with errors.")
    else:
        print("LLM judge complete.")

    print(f"\nResults in: {out_dir}")
    print("Logs in:    .run_workers/")


if __name__ == "__main__":
    main()
