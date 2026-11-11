#!/usr/bin/env python3
"""Run distribution validation locally; never publish or execute analyzed objects."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import autore_distribution as distribution

ROOT = Path(__file__).resolve().parents[1]


def run_command(argv, env, capture=False):
    print("+ " + " ".join(map(str, argv)), flush=True)
    return subprocess.run(argv, cwd=ROOT, env=env, check=True, text=True,
                          capture_output=capture)


def native_smoke(work, env):
    target = distribution.host_target()
    name = "auto-re-cli.exe" if target.startswith("windows-") else "auto-re-cli"
    expected = "auto-re-cli " + (ROOT / "VERSION").read_text().strip()
    release_cli = ROOT / "bin" / target / name
    if run_command([str(release_cli), "--version"], env, True).stdout.strip() != expected:
        raise ValueError("release CLI version differs from VERSION")
    install = work / "bin"
    codex = work / "codex"
    trae = work / "trae"
    manager = [sys.executable, "-B", str(ROOT / "scripts/autore_distribution.py")]
    destinations = ["--install-dir", str(install), "--codex-home", str(codex),
                    "--trae-home", str(trae)]
    run_command([*manager, "install", *destinations], env)
    cli = install / name
    if run_command([str(cli), "--version"], env, True).stdout.strip() != expected:
        raise ValueError("installed CLI version differs from VERSION")
    skill = codex / "skills/auto-re"
    # Scope doctor to the disposable installation, without changing real HOME registrations.
    probe = """import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('ci_doctor',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
skill=pathlib.Path(sys.argv[2])
result=m.diagnose(skill,executable=pathlib.Path(sys.argv[3]),candidate_roots=[skill])
print(json.dumps(result));sys.exit(0 if result['ok'] else 1)
"""
    run_command([sys.executable, "-B", "-c", probe, str(skill / "scripts/skill_doctor.py"),
                 str(skill), str(cli)], env)
    if not target.startswith("windows-"):
        source = work / "controlled.c"
        source.write_text("int controlled_add(int a, int b) { return a + b; }\n")
        obj = work / "controlled.o"
        run_command(["cc", "-c", str(source), "-o", str(obj)], env)
        result = work / "analysis.json"
        run_command([str(cli), "analyze", str(obj), "--format", "json", "--output", str(result)], env)
        payload = json.loads(result.read_text())
        if not isinstance(payload.get("schema_version"), str) or payload.get("metadata", {}).get("format") not in {"elf", "coff", "mach_o"}:
            raise ValueError("controlled-object analysis has an unexpected metadata contract")
    run_command([*manager, "uninstall", *destinations], env)
    if cli.exists() or skill.exists() or (trae / "skills/auto-re").exists():
        raise ValueError("uninstall retained a managed installation")


def run_ci(lane):
    builder = ROOT / "scripts/build_release_assets.py"
    if lane in {"all", "archives"} and not builder.is_file():
        raise ValueError("archive validation requires a repository checkout with build_release_assets.py")
    with tempfile.TemporaryDirectory(prefix="autore-local-ci-") as temporary:
        work = Path(temporary)
        scratch = work / "tmp"
        scratch.mkdir()
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(scratch),
                   TEMP=str(scratch), TMP=str(scratch))
        print(f"local_ci_work_dir={work}", flush=True)
        python = [sys.executable, "-B"]
        run_command([*python, str(ROOT / "scripts/autore_distribution.py"), "verify"], env)
        run_command([*python, str(ROOT / "scripts/quick_validate_skill.py"), str(ROOT / "skills/auto-re")], env)
        run_command([*python, "-m", "unittest", "discover", "-s", "tests", "-v"], env)
        if lane in {"all", "native"}:
            native_smoke(work, env)
        if lane in {"all", "archives"}:
            run_command([*python, str(builder), "--output", str(work / "release-assets")], env)
    print(f"local_ci_status=passed lane={lane}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=("all", "checks", "native", "archives"), default="all")
    args = parser.parse_args(argv)
    try:
        run_ci(args.lane)
    except (OSError, ValueError, distribution.DistributionError, subprocess.CalledProcessError) as error:
        print(f"local_ci_error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
